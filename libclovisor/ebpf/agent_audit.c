// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

/*
 * Agent Audit BPF Program - Phase 1 (audit only, never blocks)
 *
 * exec:    tp_btf/sched_process_exec. Fires once per *successful* exec,
 *          system-wide; filtered in-program to the agents cgroup subtree.
 * connect: cgroup/connect4 + cgroup/connect6, attached once to the agents
 *          cgroup (/sys/fs/cgroup/agents), so the kernel scopes it to the
 *          subtree. Every connect is reported. What else happens depends on
 *          the transparent mode (Phase 3, design §6.5 rule 1):
 *            off      allow (Phase 1 and 2 behaviour)
 *            audit    allow, reporting what enforce would have done
 *            enforce  TCP: redirect to the transparent listener, or EPERM
 *                     when the node agent's heartbeat is stale. Exceptions:
 *                     the configured addresses (explicit proxy, MCP
 *                     gateway), a loopback listener bound by the same run,
 *                     and loopback ports nobody listens on (they fail with
 *                     ECONNREFUSED as they would anyway).
 *          In audit and enforce, DNS (port 53, UDP and TCP) goes to the
 *          node agent's resolver (milestone 3.4); in enforce, refused while
 *          the heartbeat is stale. Other UDP (milestone 3.3): allowed to
 *          the configured UDP exceptions, a loopback socket bound by the
 *          same run, and loopback ports nobody listens on; refused with
 *          EPERM otherwise (QUIC included, so clients fall back to TCP at
 *          once). Audit records it and lets it through. A refused
 *          unconnected socket is reported once, not per datagram.
 *
 * sockets: BPF LSM, where active (milestones 4.1 and 4.3); filtered to
 *          tasks in runs, since global hooks see every task. In audit they
 *          report, in enforce they refuse with EPERM:
 *            socket_create   families other than IPv4, IPv6, Unix and
 *                            netlink, and raw or packet sockets;
 *            socket_connect, socket_sendmsg
 *                            a network socket created outside the run
 *                            (inherited, or passed in): its traffic would
 *                            never meet the cgroup hooks above.
 *            bprm_check_security (milestone 4.4)
 *                            exec policy, per run and layer: a resolved
 *                            path in exec.allow passes; else, under
 *                            require_trusted_path, a file failing the
 *                            trusted-path test is refused; else the
 *                            layer's default decides. Scripts are checked
 *                            again for their interpreter. An exact entry
 *                            with hashes (milestone 5.7) passes only if
 *                            the file's SHA-256, from bpf_ima_file_hash,
 *                            is one of them; that makes the hook
 *                            sleepable. Hashes are cached per inode where
 *                            the kernel's validators can be trusted.
 *            unix_stream_connect, unix_may_send (milestone 4.2)
 *                            a Unix socket bound outside the run, unless
 *                            its address matches the node's patterns (the
 *                            run API) or the run's unix.allow. Refused only
 *                            for runs with an enforcing profile; reported
 *                            once per run and address.
 *
 * backstop: cgroup_skb/egress on agents/, enforce only (in audit runs reach
 *          the network directly, so nothing is out of place). Every
 *          legitimate packet from a run goes to loopback (proxy,
 *          resolver, same-run services) or to an exception, so anything
 *          else got past the socket hooks (an unconnected ICMP datagram,
 *          a raw socket) and is dropped. Drops are reported at most once a
 *          second per run, with a count.
 *
 * dns:     cgroup/sendmsg4,6 send unconnected port-53 datagrams to the
 *          resolver too; cgroup/recvmsg4,6 make its replies appear to come
 *          from the server the client asked, which resolvers check.
 *
 * transparent (mode audit or enforce, milestone 3.1):
 *          cgroup/bind4,6 on agents/ tag each socket with its run, for the
 *          same-run loopback check. sockops on agents/ re-keys a redirected
 *          socket's original destination by its local address and port,
 *          which is what the proxy sees as its peer. cgroup/getpeername4,6
 *          on agents/ report the original peer. cgroup/getsockopt, on the
 *          cgroup root, answers SO_ORIGINAL_DST for tasks outside agents/
 *          (the proxy). In enforce mode these links are pinned, so they
 *          outlive the node agent and connects fail closed when it dies.
 *
 * Syscall tracepoints (syscalls/sys_enter_*) are deliberately not used:
 * attached via perf_event they only fire on the CPU the perf event was
 * opened on with current kernels.
 *
 * run:     tp_btf/cgroup_mkdir + cgroup_rmdir, for cgroups one level below
 *          agents/, mark the start and end of a run. A run cgroup can only
 *          be removed once every task in it has exited, and all events go
 *          through one ring buffer, so the rmdir event is always the last
 *          event of its run.
 *
 * dns:     cgroup_skb/ingress on agents/ copies UDP datagrams from port 53
 *          (resolver replies) to userspace, which parses them. The packet is
 *          attributed to the receiving socket's cgroup, so no pid is known.
 *          Always returns 1 (deliver).
 *
 * Each event carries the leaf cgroup id and the run cgroup id (the
 * agents/run-<id> ancestor), so tool-call child cgroups roll up to the run.
 * All events go through a single ring buffer.
 */

#include <linux/bpf.h>
#include <asm/ptrace.h> /* pt_regs for the uprobes (milestone 6.2) */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define MAX_PATH_LEN   256
#define MAX_ARGS_LEN   512  /* power of two: used as a mask */
#define MAX_CGPATH_LEN 128
#define MAX_DNS_LEN    1024 /* power of two: used as a mask */
#define MAX_NEST       3    /* nested runs below a run (milestone 4.6) */

#define ETH_P_IP     0x0800
#define ETH_P_IPV6   0x86DD
#define IPPROTO_UDP  17
#define IPPROTO_TCP_ 6
#define IPPROTO_ICMP_   1
#define IPPROTO_ICMPV6_ 58
#define ICMP_ECHO_      8
#define ICMPV6_ECHO_    128
#define DNS_PORT     53

#define SOCK_STREAM 1
#define SOCK_DGRAM  2

#define AF_INET  2
#define AF_INET6 10

#define EVENT_EXEC    0
#define EVENT_CONNECT 1
#define EVENT_RUN_START 2
#define EVENT_RUN_END   3
#define EVENT_DNS       4
#define EVENT_DROP      5
#define EVENT_SOCKET    6
#define EVENT_UNIX      7
#define EVENT_EXEC_PATH 8
#define EVENT_TLS_EXEC  9  /* a process to attach TLS probes to (milestone 6.2) */
#define EVENT_TLS_EXIT  10 /* a process with TLS probes exited */
#define EVENT_TLS_DATA  11 /* plaintext a TLS library wrote or read */

/* CO-RE: only the fields we need; relocated against kernel BTF at load. */
struct file;

struct linux_binprm {
    const char *filename;
    struct file *file;
} __attribute__((preserve_access_index));

typedef struct {
    unsigned int val;
} kuid_t___c;

struct super_block {
    __u32 s_dev;
    unsigned long s_flags;
    unsigned long s_magic;
} __attribute__((preserve_access_index));

typedef struct {
    int counter;
} atomic_t___c;

typedef struct {
    __s64 counter;
} atomic64_t___c;

struct inode {
    unsigned short i_mode;
    kuid_t___c i_uid;
    struct super_block *i_sb;
    unsigned long i_ino;
    __u32 i_generation;
    atomic64_t___c i_version;
    atomic_t___c i_writecount;
    __s64 i_ctime_sec;  /* 6.11 and later */
    __u32 i_ctime_nsec;
} __attribute__((preserve_access_index));

struct timespec64___c {
    __s64 tv_sec;
    long tv_nsec;
};

/* Before 6.11 the change time was one timespec64. */
struct inode___ctime {
    struct timespec64___c __i_ctime;
} __attribute__((preserve_access_index));

struct dentry {
    struct dentry *d_parent;
    struct inode *d_inode;
} __attribute__((preserve_access_index));

struct vfsmount {
    struct dentry *mnt_root;
} __attribute__((preserve_access_index));

struct mount {
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
} __attribute__((preserve_access_index));

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
    struct path f_path;
    struct inode *f_inode;
} __attribute__((preserve_access_index));

struct mm_struct {
    unsigned long arg_start;
    unsigned long arg_end;
} __attribute__((preserve_access_index));

struct task_struct {
    int tgid;
    struct task_struct *real_parent;
    struct mm_struct *mm;
} __attribute__((preserve_access_index));

struct kernfs_node {
    const char *name;
    __u64 id;
} __attribute__((preserve_access_index));

struct cgroup {
    struct kernfs_node *kn;
    int level;
} __attribute__((preserve_access_index));

/* A cgroup's ancestors by level: pointers since 6.2, ids before. The
 * ___flavours let CO-RE pick whichever the running kernel has. */
struct cgroup___ptrs {
    struct cgroup *ancestors[1];
} __attribute__((preserve_access_index));

struct cgroup___ids {
    __u64 ancestor_ids[1];
} __attribute__((preserve_access_index));

struct sock_cgroup_data {
    struct cgroup *cgroup;
} __attribute__((preserve_access_index));

struct sock_common {
    unsigned short skc_family;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
    struct sock_cgroup_data sk_cgrp_data;
} __attribute__((preserve_access_index));

struct socket {
    struct sock *sk;
} __attribute__((preserve_access_index));

struct sockaddr_un_k {
    unsigned short sun_family;
    char sun_path[108];
};

struct unix_address {
    int len;
    struct sockaddr_un_k name[1];
} __attribute__((preserve_access_index));

struct unix_sock {
    struct unix_address *addr;
} __attribute__((preserve_access_index));

#define MAX_EXCEPTIONS 4

#define MODE_OFF     0
#define MODE_AUDIT   1
#define MODE_ENFORCE 2

/* Connect verdicts, reported in connect_event.verdict. */
#define V_NONE           0 /* mode off */
#define V_REDIRECT       1
#define V_DENY_UNHEALTHY 2
#define V_SAME_RUN       3
#define V_EXCEPTION      4
#define V_UNBOUND        5 /* loopback, nobody listening: left alone */
#define V_AUDIT_REDIRECT 6
#define V_AUDIT_DENY     7
#define V_DNS            8 /* port 53, to the local resolver */
#define V_UDP_DENY       9
#define V_AUDIT_UDP      10
#define V_SOCK_DENY      11 /* family, raw socket, or foreign socket */
#define V_AUDIT_SOCK     12
#define V_UNIX_DENY      13 /* a Unix socket outside the run */
#define V_AUDIT_UNIX     14
#define V_EXEC_OK        15 /* an exec, allowed (reported once per path) */
#define V_EXEC_DENY      16
#define V_AUDIT_EXEC     17
#define V_QUIC           18 /* UDP 443, to the node agent's QUIC relay (milestone 5.6) */

/* Addresses as 16 bytes, network order, IPv4 as ::ffff:a.b.c.d. */
struct addr {
    __u32 a[4];
};

/* An address runs reach directly. An all-zero ip means any loopback. */
struct exception {
    struct addr ip;
    __u16 port;           /* host order; 0 ends the list */
    __u16 _pad;
    __u32 _pad2;
};

/* Written by the node agent at start. */
struct audit_config {
    __u64 agents_cgroup_id;
    __u32 agents_level;   /* depth of agents dir below cgroup root */
    __u32 mode;           /* MODE_* */
    __u64 stale_ns;       /* heartbeat older than this: unhealthy */
    __u16 tproxy_port;    /* transparent listener on 127.0.0.1 and ::1, host order */
    __u16 dns_port;       /* local resolver on 127.0.0.1 and ::1, host order; 0: none */
    __u16 quic_port;      /* QUIC relay on 127.0.0.1 and ::1, host order; 0: none (milestone 5.6) */
    __u16 _pad2;
    struct exception exc[MAX_EXCEPTIONS];
    struct exception udp_exc[MAX_EXCEPTIONS]; /* UDP destinations runs may reach */
};

/* Original destination of a redirected socket. */
struct orig {
    struct addr ip;
    __u16 port;           /* network order */
    __u16 family;         /* of the original destination */
    __u32 _pad;
};

struct tuple_key {
    struct addr ip;       /* the client's local address */
    __u16 port;           /* the client's local port, network order */
    __u16 _pad;
    __u32 _pad2;
};

struct event_hdr {
    __u32 type;
    __u32 pid;            /* tgid */
    __u64 timestamp_ns;   /* CLOCK_BOOTTIME */
    __u64 cgroup_id;      /* leaf cgroup of the task */
    __u64 run_cgroup_id;  /* agents/run-<id> ancestor */
};

struct exec_event {
    struct event_hdr hdr;
    __u32 ppid;
    __u32 args_len;       /* bytes of args used; NUL-separated argv */
    char filename[MAX_PATH_LEN];
    char args[MAX_ARGS_LEN];
};

struct connect_event {
    struct event_hdr hdr;
    __u16 family;
    __u16 dport;          /* host byte order */
    __u32 protocol;       /* IPPROTO_TCP / IPPROTO_UDP */
    __u8  daddr[16];      /* v4 in first 4 bytes, network order */
    __u32 verdict;        /* V_* */
    __u32 _pad;
};

/* A socket refused (or, in audit, that would be): an unusual family or a
 * raw socket at creation (milestone 4.1), or a network socket created
 * outside the run, at connect or send (4.3). */
struct socket_event {
    struct event_hdr hdr;
    __u16 family;
    __u16 type;           /* creation only */
    __u32 protocol;       /* creation only */
    __u32 op;             /* SOCK_OP_* */
    __u32 verdict;        /* V_* */
    __u64 sk_cgroup;      /* cgroup the socket was created in (connect, send) */
};

/* A Unix socket outside the run (milestone 4.2). */
struct unix_event {
    struct event_hdr hdr;
    __u8  path[112];      /* filesystem path, or @name for an abstract one */
    __u32 len;
    __u32 verdict;        /* V_* */
    __u32 dgram;
    __u32 _pad;
    __u64 peer_cgroup;    /* cgroup the listening socket was created in */
};

#define MAX_UNIX_PATTERNS 8
#define UNIX_WORDS        14 /* 112 bytes */

/* m holds a mask over the pattern's len bytes, computed by the node agent,
 * so matching is a fixed sequence of masked compares with no branches:
 * the verifier would otherwise explore every early exit. */
struct unix_pat {
    __u16 len;
    __u8  prefix;         /* a trailing * */
    __u8  _pad[5];
    __u64 b[UNIX_WORDS];
    __u64 m[UNIX_WORDS];
};

struct unix_policy {
    __u32 n;
    __u32 enforce;        /* the run has an enforcing profile */
    struct unix_pat p[MAX_UNIX_PATTERNS];
};

#define SOCK_OP_CREATE  0
#define SOCK_OP_CONNECT 1
#define SOCK_OP_SEND    2

/* Packets the backstop dropped (or, in audit, would have). pid is 0. */
struct drop_event {
    struct event_hdr hdr;
    __u16 family;
    __u16 dport;          /* host byte order; 0 if not TCP or UDP */
    __u32 protocol;       /* IP protocol */
    __u8  daddr[16];      /* v4 in first 4 bytes, network order */
    __u32 count;          /* packets since the last report */
    __u32 enforced;       /* 1: dropped; 0: audit, let through */
};

/* hdr.cgroup_id and hdr.run_cgroup_id are both the run cgroup's id. */
struct cgroup_event {
    struct event_hdr hdr;
    char path[MAX_CGPATH_LEN]; /* relative to the cgroup root, e.g. /agents/run-x */
};

struct dns_event {
    struct event_hdr hdr;     /* pid is 0: softirq context */
    __u16 family;
    __u16 _pad;
    __u32 len;                /* bytes of payload captured */
    __u32 orig_len;           /* DNS message length on the wire */
    __u8  saddr[16];          /* resolver that answered */
    __u8  payload[MAX_DNS_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct audit_config);
} config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 << 20); /* each run may use a quarter: RUN_BURST */
} events SEC(".maps");

/*
 * Events lost to a full ring buffer (milestone 3.5): per run, so the
 * timeline can say it is incomplete, and in total at key 0. Run ids are
 * cgroup ids, never 0.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} lost SEC(".maps");

static __always_inline void count_lost(__u64 key)
{
    __u64 *n = bpf_map_lookup_elem(&lost, &key);
    if (n) {
        __sync_fetch_and_add(n, 1);
        return;
    }
    __u64 one = 1;
    if (bpf_map_update_elem(&lost, &key, &one, BPF_NOEXIST) != 0) {
        n = bpf_map_lookup_elem(&lost, &key);
        if (n)
            __sync_fetch_and_add(n, 1);
    }
}

static __always_inline void note_lost(__u64 run)
{
    count_lost(0);
    if (run)
        count_lost(run);
}

/*
 * Per-run event budget (after milestone 3.5): one run cannot fill the ring
 * buffer every run shares. A token bucket in bytes, so exec and connect
 * events are charged by size: RUN_BURST at once, RUN_RATE a second after
 * that. Events over budget are not reported, and are counted per run (and
 * in total at key 0) so the timeline can say so; enforcement does not
 * depend on reporting. Run start and end are never charged. Updates race
 * between CPUs, which makes the budget approximate, not unsafe.
 */
#define RUN_RATE  (4 << 20) /* bytes per second: about 5000 execs or 70000 connects */
#define RUN_BURST (1 << 20) /* bytes, a quarter of the ring buffer: about 1300 execs */

struct budget {
    __u64 tokens;
    __u64 last_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct budget);
} run_budget SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} suppressed SEC(".maps");

static __always_inline void count_suppressed(__u64 key)
{
    __u64 *n = bpf_map_lookup_elem(&suppressed, &key);
    if (n) {
        __sync_fetch_and_add(n, 1);
        return;
    }
    __u64 one = 1;
    if (bpf_map_update_elem(&suppressed, &key, &one, BPF_NOEXIST) != 0) {
        n = bpf_map_lookup_elem(&suppressed, &key);
        if (n)
            __sync_fetch_and_add(n, 1);
    }
}

/* Charge size bytes to run's budget; 0 means do not report the event. */
static __always_inline int within_budget(__u64 run, __u32 size)
{
    if (run == 0)
        return 1;
    __u64 now = bpf_ktime_get_ns();
    struct budget *b = bpf_map_lookup_elem(&run_budget, &run);
    if (!b) {
        struct budget fresh = {.tokens = RUN_BURST - size, .last_ns = now};
        bpf_map_update_elem(&run_budget, &run, &fresh, BPF_NOEXIST);
        return 1;
    }
    __u64 elapsed = now - b->last_ns;
    if (elapsed > 1000000000ULL)
        elapsed = 1000000000ULL;
    __u64 tokens = b->tokens + elapsed * RUN_RATE / 1000000000ULL;
    if (tokens > RUN_BURST)
        tokens = RUN_BURST;
    b->last_ns = now;
    if (tokens < size) {
        b->tokens = tokens;
        count_suppressed(0);
        count_suppressed(run);
        return 0;
    }
    b->tokens = tokens - size;
    return 1;
}

/* CLOCK_MONOTONIC ns of the node agent's last heartbeat. Its own map, so a
 * heartbeat never rewrites the config another CPU is reading. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} heartbeat SEC(".maps");

/* Original destination of a redirected socket, freed with the socket. */
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct orig);
} orig_by_sk SEC(".maps");

/* Run cgroup id of the task that bound the socket. */
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, __u64);
} run_by_sk SEC(".maps");

/* Unconnected UDP sockets whose refusal was already reported. */
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, __u32);
} udp_reported SEC(".maps");

/* Backstop reporting, per run: last report time and drops since. */
struct drop_state {
    __u64 last_ns;
    __u32 count;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct drop_state);
} drop_rate SEC(".maps");

/* Per run: its effective unix.allow, written by the node agent at bind
 * and clamp (milestone 4.2). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct unix_policy);
} unix_policy SEC(".maps");

/* Node-wide patterns: the run API. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct unix_policy);
} unix_node SEC(".maps");

struct unix_seen_key {
    __u64 run;
    __u64 hash;
};

/* Unix addresses already reported for a run. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct unix_seen_key);
    __type(value, __u8);
} unix_seen SEC(".maps");

/* The proxy's view: its peer (the client) to the original destination. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct tuple_key);
    __type(value, struct orig);
} orig_by_tuple SEC(".maps");

/*
 * A direct 32-bit load of a ctx or sock field. Plain C lets the compiler fold
 * loads of neighbouring fields behind a branch into one load at a computed
 * offset, which the verifier refuses for sock and ctx pointers (3.0 spike).
 */
#define LOAD32(ptr, type, field) ({                                            \
    __u32 __v;                                                                \
    asm volatile("%0 = *(u32 *)(%1 + %2)"                                     \
                 : "=r"(__v) : "r"(ptr), "i"(__builtin_offsetof(type, field))); \
    __v; })

/*
 * Returns nonzero if the current task lives in a run cgroup under the
 * agents subtree, and fills in the common header.
 */
static __always_inline int fill_hdr(struct event_hdr *hdr, __u32 type)
{
    __u32 zero = 0;
    struct audit_config *cfg = bpf_map_lookup_elem(&config, &zero);
    if (!cfg || cfg->agents_cgroup_id == 0)
        return 0;

    if (bpf_get_current_ancestor_cgroup_id(cfg->agents_level) != cfg->agents_cgroup_id)
        return 0;

    __u64 run = bpf_get_current_ancestor_cgroup_id(cfg->agents_level + 1);
    if (run == 0)
        return 0; /* task sits directly in agents/, not in a run */

    hdr->type = type;
    hdr->pid = bpf_get_current_pid_tgid() >> 32;
    hdr->timestamp_ns = bpf_ktime_get_boot_ns();
    hdr->cgroup_id = bpf_get_current_cgroup_id();
    hdr->run_cgroup_id = run;
    return 1;
}

/* sched_process_exec(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm) */
SEC("tp_btf/sched_process_exec")
int on_exec(__u64 *ctx)
{
    struct event_hdr hdr = {};
    if (!fill_hdr(&hdr, EVENT_EXEC))
        return 0;

    struct linux_binprm *bprm = (struct linux_binprm *)ctx[2];

    if (!within_budget(hdr.run_cgroup_id, sizeof(struct exec_event)))
        return 0;
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        note_lost(hdr.run_cgroup_id);
        return 0;
    }

    e->hdr = hdr;
    const char *fname = BPF_CORE_READ(bprm, filename);
    if (bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fname) < 0)
        e->filename[0] = '\0';

    struct task_struct *task = (struct task_struct *)ctx[0];
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    /* argv lives in the new image's user memory, already written by exec. */
    unsigned long start = BPF_CORE_READ(task, mm, arg_start);
    unsigned long end = BPF_CORE_READ(task, mm, arg_end);
    __u32 len = 0;
    if (end > start) {
        len = end - start;
        if (len > MAX_ARGS_LEN)
            len = MAX_ARGS_LEN;
        if (bpf_probe_read_user(e->args, len & (MAX_ARGS_LEN - 1) ?: MAX_ARGS_LEN,
                                (const void *)start) < 0)
            len = 0;
    }
    e->args_len = len;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline void emit_connect(struct bpf_sock_addr *ctx, __u16 family, struct addr *ip, __u16 dport, __u32 verdict)
{
    struct event_hdr hdr = {};
    if (!fill_hdr(&hdr, EVENT_CONNECT))
        return;

    if (!within_budget(hdr.run_cgroup_id, sizeof(struct connect_event)))
        return;
    struct connect_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        note_lost(hdr.run_cgroup_id);
        return;
    }

    e->hdr = hdr;
    e->family = family;
    e->dport = bpf_ntohs(dport);
    e->protocol = ctx->protocol;
    e->verdict = verdict;
    e->_pad = 0;
    __builtin_memset(e->daddr, 0, sizeof(e->daddr));
    if (family == AF_INET)
        __builtin_memcpy(e->daddr, &ip->a[3], 4);
    else
        __builtin_memcpy(e->daddr, ip->a, 16);

    bpf_ringbuf_submit(e, 0);
}

static __always_inline void emit_cgroup(struct cgroup *cgrp, const char *path, __u32 type)
{
    __u32 zero = 0;
    struct audit_config *cfg = bpf_map_lookup_elem(&config, &zero);
    if (!cfg || cfg->agents_cgroup_id == 0)
        return;
    __u32 level = BPF_CORE_READ(cgrp, level);
    if (level != cfg->agents_level + 1) {
        /* A nested run (milestone 4.6), run-<id> below a run, starts and
         * ends a timeline too; calls and MCP servers do not. */
        if (level < cfg->agents_level + 2 || level > cfg->agents_level + 1 + MAX_NEST)
            return;
        char name[4] = {};
        bpf_probe_read_kernel(name, sizeof(name), BPF_CORE_READ(cgrp, kn, name));
        if (name[0] != 'r' || name[1] != 'u' || name[2] != 'n' || name[3] != '-')
            return;
    } /* the node agent checks the path is under agents/ */

    __u64 id = BPF_CORE_READ(cgrp, kn, id);
    struct cgroup_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        note_lost(id);
        return;
    }

    e->hdr.type = type;
    e->hdr.pid = bpf_get_current_pid_tgid() >> 32;
    e->hdr.timestamp_ns = bpf_ktime_get_boot_ns();
    e->hdr.cgroup_id = id;
    e->hdr.run_cgroup_id = id;
    if (bpf_probe_read_kernel_str(e->path, sizeof(e->path), path) < 0)
        e->path[0] = '\0';

    bpf_ringbuf_submit(e, 0);
}

/* cgroup_mkdir(struct cgroup *cgrp, const char *path) */
SEC("tp_btf/cgroup_mkdir")
int on_cgroup_mkdir(__u64 *ctx)
{
    emit_cgroup((struct cgroup *)ctx[0], (const char *)ctx[1], EVENT_RUN_START);
    return 0;
}

/* cgroup_rmdir(struct cgroup *cgrp, const char *path) */
SEC("tp_btf/cgroup_rmdir")
int on_cgroup_rmdir(__u64 *ctx)
{
    emit_cgroup((struct cgroup *)ctx[0], (const char *)ctx[1], EVENT_RUN_END);
    return 0;
}

/*
 * skb->data starts at the network header for cgroup_skb programs. Only
 * plain UDP from port 53 is captured; IPv6 extension headers are not
 * walked (resolver replies do not carry them).
 */
SEC("cgroup_skb/ingress")
int on_ingress(struct __sk_buff *skb)
{
    __u32 zero = 0;
    struct audit_config *cfg = bpf_map_lookup_elem(&config, &zero);
    if (!cfg || cfg->agents_cgroup_id == 0)
        return 1;

    __u32 l4off;
    __u16 family;
    __u8 saddr[16] = {};

    if (skb->protocol == bpf_htons(ETH_P_IP)) {
        __u8 vihl, proto;
        if (bpf_skb_load_bytes(skb, 0, &vihl, 1) < 0 ||
            bpf_skb_load_bytes(skb, 9, &proto, 1) < 0)
            return 1;
        if (proto != IPPROTO_UDP)
            return 1;
        l4off = (vihl & 0x0f) * 4;
        if (bpf_skb_load_bytes(skb, 12, saddr, 4) < 0)
            return 1;
        family = AF_INET;
    } else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
        __u8 nexthdr;
        if (bpf_skb_load_bytes(skb, 6, &nexthdr, 1) < 0)
            return 1;
        if (nexthdr != IPPROTO_UDP)
            return 1;
        l4off = 40;
        if (bpf_skb_load_bytes(skb, 8, saddr, 16) < 0)
            return 1;
        family = AF_INET6;
    } else {
        return 1;
    }

    __u16 udp[4]; /* sport, dport, len, csum */
    if (bpf_skb_load_bytes(skb, l4off, udp, sizeof(udp)) < 0)
        return 1;
    if (udp[0] != bpf_htons(DNS_PORT))
        return 1;

    if (bpf_skb_ancestor_cgroup_id(skb, cfg->agents_level) != cfg->agents_cgroup_id)
        return 1;
    __u64 run = bpf_skb_ancestor_cgroup_id(skb, cfg->agents_level + 1);
    if (run == 0)
        return 1;

    __u32 dnslen = bpf_ntohs(udp[2]);
    if (dnslen <= 8 + 12) /* UDP header + DNS header */
        return 1;
    dnslen -= 8;

    if (!within_budget(run, sizeof(struct dns_event)))
        return 1;
    struct dns_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        note_lost(run);
        return 1;
    }

    e->hdr.type = EVENT_DNS;
    e->hdr.pid = 0;
    e->hdr.timestamp_ns = bpf_ktime_get_boot_ns();
    e->hdr.cgroup_id = bpf_skb_cgroup_id(skb);
    e->hdr.run_cgroup_id = run;
    e->family = family;
    e->_pad = 0;
    e->orig_len = dnslen;
    __builtin_memcpy(e->saddr, saddr, sizeof(saddr));

    __u32 len = dnslen > MAX_DNS_LEN ? MAX_DNS_LEN : dnslen;
    /* 1 to MAX_DNS_LEN, in a form older verifiers can see is never zero
     * (7.2: 6.6 refused "len & (MAX_DNS_LEN - 1) ?: MAX_DNS_LEN" as a
     * possibly zero-sized read). The same length for every len. */
    __u32 n = ((len - 1) & (MAX_DNS_LEN - 1)) + 1;
    if (bpf_skb_load_bytes(skb, l4off + 8, e->payload, n) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 1;
    }
    e->len = len;

    bpf_ringbuf_submit(e, 0);
    return 1;
}

static __always_inline struct audit_config *get_config(void)
{
    __u32 zero = 0;
    struct audit_config *cfg = bpf_map_lookup_elem(&config, &zero);
    if (!cfg || cfg->agents_cgroup_id == 0)
        return 0;
    return cfg;
}

/* Run cgroup id of the current task, 0 if it is not in a run. */
static __always_inline __u64 current_run(struct audit_config *cfg)
{
    if (bpf_get_current_ancestor_cgroup_id(cfg->agents_level) != cfg->agents_cgroup_id)
        return 0;
    return bpf_get_current_ancestor_cgroup_id(cfg->agents_level + 1);
}

/* Nested runs (milestone 4.6): a run started from inside a run, in a
 * cgroup below it, with its own entries in the per-run policy maps.
 * Written by the node agent before any process enters the cgroup. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} nested_run SEC(".maps");

/* The nearest run of the current task, for per-run policy: the deepest
 * nested run it is in, else its run. Events stay keyed by the run, whose
 * budget the whole tree shares. */
static __always_inline __u64 policy_run(struct audit_config *cfg, __u64 run)
{
#pragma unroll
    for (int i = MAX_NEST; i >= 1; i--) {
        __u64 id = bpf_get_current_ancestor_cgroup_id(cfg->agents_level + 1 + i);
        if (id && bpf_map_lookup_elem(&nested_run, &id))
            return id;
    }
    return run;
}

/* As policy_run, for a packet: by its socket's cgroup. */
static __always_inline __u64 skb_policy_run(struct __sk_buff *skb, struct audit_config *cfg, __u64 run)
{
#pragma unroll
    for (int i = MAX_NEST; i >= 1; i--) {
        __u64 id = bpf_skb_ancestor_cgroup_id(skb, cfg->agents_level + 1 + i);
        if (id && bpf_map_lookup_elem(&nested_run, &id))
            return id;
    }
    return run;
}

/* Per run (milestone 4.7): UDP destinations and ICMP echo prefixes the
 * run's ceiling and profile both allow, beyond the node's exceptions. */
#define MAX_RUN_UDP  8
#define MAX_RUN_ICMP 8

struct icmp_prefix {
    struct addr ip;       /* masked, IPv4 as ::ffff:a.b.c.d */
    struct addr mask;     /* all zero: unused */
};

struct net_policy {
    struct exception udp[MAX_RUN_UDP];   /* port 0 ends the list */
    struct icmp_prefix icmp[MAX_RUN_ICMP];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct net_policy);
} run_net SEC(".maps");

static __always_inline int run_udp_ok(struct net_policy *np, struct addr *ip, __u16 hport)
{
    if (!np)
        return 0;
#pragma unroll
    for (int i = 0; i < MAX_RUN_UDP; i++) {
        struct exception *x = &np->udp[i];
        if (x->port == 0)
            break;
        if (x->port == hport && x->ip.a[0] == ip->a[0] && x->ip.a[1] == ip->a[1] &&
            x->ip.a[2] == ip->a[2] && x->ip.a[3] == ip->a[3])
            return 1;
    }
    return 0;
}

static __always_inline int run_icmp_ok(struct net_policy *np, struct addr *ip)
{
    if (!np)
        return 0;
#pragma unroll
    for (int i = 0; i < MAX_RUN_ICMP; i++) {
        struct icmp_prefix *x = &np->icmp[i];
        __u32 any = x->mask.a[0] | x->mask.a[1] | x->mask.a[2] | x->mask.a[3];
        if (any && (ip->a[0] & x->mask.a[0]) == x->ip.a[0] && (ip->a[1] & x->mask.a[1]) == x->ip.a[1] &&
            (ip->a[2] & x->mask.a[2]) == x->ip.a[2] && (ip->a[3] & x->mask.a[3]) == x->ip.a[3])
            return 1;
    }
    return 0;
}

static __always_inline int healthy(struct audit_config *cfg)
{
    __u32 zero = 0;
    __u64 *hb = bpf_map_lookup_elem(&heartbeat, &zero);
    if (!hb || *hb == 0)
        return 0;
    return bpf_ktime_get_ns() - *hb < cfg->stale_ns;
}

static __always_inline void v4mapped(struct addr *a, __u32 ip4)
{
    a->a[0] = 0;
    a->a[1] = 0;
    a->a[2] = bpf_htonl(0x0000ffff);
    a->a[3] = ip4;
}

static __always_inline int is_v4mapped(struct addr *a)
{
    return a->a[0] == 0 && a->a[1] == 0 && a->a[2] == bpf_htonl(0x0000ffff);
}

static __always_inline int is_loopback(struct addr *a)
{
    if (is_v4mapped(a))
        return (bpf_ntohl(a->a[3]) >> 24) == 127;
    return a->a[0] == 0 && a->a[1] == 0 && a->a[2] == 0 && a->a[3] == bpf_htonl(1);
}

static __always_inline int in_exceptions(struct exception *list, struct addr *ip, __u16 hport)
{
#pragma unroll
    for (int i = 0; i < MAX_EXCEPTIONS; i++) {
        struct exception *x = &list[i];
        if (x->port == 0)
            break;
        if (x->port != hport)
            continue;
        if (x->ip.a[0] == 0 && x->ip.a[1] == 0 && x->ip.a[2] == 0 && x->ip.a[3] == 0) {
            if (is_loopback(ip))
                return 1;
            continue;
        }
        if (x->ip.a[0] == ip->a[0] && x->ip.a[1] == ip->a[1] &&
            x->ip.a[2] == ip->a[2] && x->ip.a[3] == ip->a[3])
            return 1;
    }
    return 0;
}

#define LISTENER_NONE  0
#define LISTENER_SAME  1
#define LISTENER_OTHER 2

/*
 * Who listens at ip:port: nobody, this run (the socket was bound by it), or
 * someone else. With nobody listening the connect is left alone: it fails
 * with ECONNREFUSED, as it would without Clovisor, and a client trying ::1
 * before 127.0.0.1 falls back (3.0 spike).
 */
static __always_inline int loopback_listener(struct bpf_sock_addr *ctx, struct addr *ip, __u16 port, __u64 run, int udp)
{
    struct bpf_sock_tuple t = {};
    struct bpf_sock *sk;

    if (is_v4mapped(ip)) {
        t.ipv4.daddr = ip->a[3];
        t.ipv4.dport = port;
        sk = udp ? bpf_sk_lookup_udp(ctx, &t, sizeof(t.ipv4), BPF_F_CURRENT_NETNS, 0)
                 : bpf_sk_lookup_tcp(ctx, &t, sizeof(t.ipv4), BPF_F_CURRENT_NETNS, 0);
    } else {
        __builtin_memcpy(t.ipv6.daddr, ip->a, 16);
        t.ipv6.dport = port;
        sk = udp ? bpf_sk_lookup_udp(ctx, &t, sizeof(t.ipv6), BPF_F_CURRENT_NETNS, 0)
                 : bpf_sk_lookup_tcp(ctx, &t, sizeof(t.ipv6), BPF_F_CURRENT_NETNS, 0);
    }
    if (!sk)
        return LISTENER_NONE;
    int who = LISTENER_OTHER;
    __u64 *owner = bpf_sk_storage_get(&run_by_sk, sk, 0, 0);
    if (owner && *owner == run)
        who = LISTENER_SAME;
    bpf_sk_release(sk);
    return who;
}

/*
 * The connect decision. Returns the verdict; *rewrite is set when the
 * destination must be rewritten to the transparent listener.
 */
static __always_inline __u32 decide(struct bpf_sock_addr *ctx, struct audit_config *cfg, __u64 run,
                                    struct addr *ip, __u16 port, __u16 *to_port)
{
    *to_port = 0;
    if (cfg->mode == MODE_OFF)
        return V_NONE;
    __u16 hport = bpf_ntohs(port);
    __u32 type = ctx->type;

    /* DNS goes to the resolver in audit too: it answers everything there,
     * recording what enforce would refuse. */
    if (hport == 53 && cfg->dns_port != 0 && (type == SOCK_DGRAM || type == SOCK_STREAM)) {
        if (!healthy(cfg))
            return cfg->mode == MODE_ENFORCE ? V_DENY_UNHEALTHY : V_AUDIT_DENY;
        *to_port = cfg->dns_port;
        return V_DNS;
    }
    if (type == SOCK_DGRAM) {
        __u32 proto = LOAD32(ctx, struct bpf_sock_addr, protocol);
        if (proto == IPPROTO_ICMP_ || proto == IPPROTO_ICMPV6_)
            return V_NONE; /* a ping socket: the egress backstop decides each echo */
        if (in_exceptions(cfg->udp_exc, ip, hport))
            return V_EXCEPTION;
        __u64 prun = policy_run(cfg, run);
        if (run_udp_ok(bpf_map_lookup_elem(&run_net, &prun), ip, hport))
            return V_EXCEPTION;
        if (is_loopback(ip)) {
            if ((hport == cfg->dns_port && cfg->dns_port != 0) || (hport == cfg->quic_port && cfg->quic_port != 0))
                return V_EXCEPTION;
            int who = loopback_listener(ctx, ip, port, run, 1);
            if (who == LISTENER_SAME)
                return V_SAME_RUN;
            if (who == LISTENER_NONE)
                return V_UNBOUND;
        } else if (hport == 443 && cfg->quic_port != 0 && cfg->mode == MODE_ENFORCE) {
            /* QUIC by name (milestone 5.6): the relay reads the server
             * name from the Initial and decides it, as for TLS. */
            if (!healthy(cfg))
                return V_DENY_UNHEALTHY;
            *to_port = cfg->quic_port;
            return V_QUIC;
        }
        return cfg->mode == MODE_ENFORCE ? V_UDP_DENY : V_AUDIT_UDP;
    }
    if (type != SOCK_STREAM)
        return V_NONE;
    if (in_exceptions(cfg->exc, ip, hport))
        return V_EXCEPTION;
    if (is_loopback(ip)) {
        if (hport == cfg->dns_port && cfg->dns_port != 0)
            return V_EXCEPTION;
        int who = loopback_listener(ctx, ip, port, run, 0);
        if (who == LISTENER_SAME)
            return V_SAME_RUN;
        if (who == LISTENER_NONE)
            return V_UNBOUND;
    }
    int ok = healthy(cfg);
    if (cfg->mode != MODE_ENFORCE)
        return ok ? V_AUDIT_REDIRECT : V_AUDIT_DENY;
    if (!ok)
        return V_DENY_UNHEALTHY;
    *to_port = cfg->tproxy_port;
    return V_REDIRECT;
}

static __always_inline void stash(struct bpf_sock_addr *ctx, struct addr *ip, __u16 port, __u16 family)
{
    struct orig *o = bpf_sk_storage_get(&orig_by_sk, ctx->sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (!o)
        return;
    o->ip = *ip;
    o->port = port;
    o->family = family;
    o->_pad = 0;
}

/* Apply a verdict: refuse, or rewrite to 127.0.0.1:to, remembering the
 * original destination. Returns the hook's return value. */
static __always_inline int rewrite4(struct bpf_sock_addr *ctx, struct addr *ip, __u16 port, __u32 v, __u16 to)
{
    if (v == V_DENY_UNHEALTHY || v == V_UDP_DENY)
        return 0;
    if (to) {
        stash(ctx, ip, port, AF_INET);
        ctx->user_ip4 = bpf_htonl(0x7f000001);
        ctx->user_port = bpf_htons(to);
    }
    return 1;
}

static __always_inline int rewrite6(struct bpf_sock_addr *ctx, struct addr *ip, __u16 port, __u32 v, __u16 to)
{
    if (v == V_DENY_UNHEALTHY || v == V_UDP_DENY)
        return 0;
    if (to) {
        int mapped = is_v4mapped(ip);
        stash(ctx, ip, port, mapped ? AF_INET : AF_INET6);
        if (mapped) {
            /* Dual-stack socket to an IPv4 address: keep it IPv4. */
            ctx->user_ip6[3] = bpf_htonl(0x7f000001);
        } else {
            ctx->user_ip6[0] = 0;
            ctx->user_ip6[1] = 0;
            ctx->user_ip6[2] = 0;
            ctx->user_ip6[3] = bpf_htonl(1);
        }
        ctx->user_port = bpf_htons(to);
    }
    return 1;
}

SEC("cgroup/connect4")
int on_connect4(struct bpf_sock_addr *ctx)
{
    struct audit_config *cfg = get_config();
    if (!cfg)
        return 1;
    __u64 run = current_run(cfg);
    if (run == 0)
        return 1;
    struct addr ip;
    v4mapped(&ip, ctx->user_ip4);
    __u16 port = (__u16)ctx->user_port;
    __u16 to;
    __u32 v = decide(ctx, cfg, run, &ip, port, &to);
    emit_connect(ctx, AF_INET, &ip, port, v);
    return rewrite4(ctx, &ip, port, v, to);
}

SEC("cgroup/connect6")
int on_connect6(struct bpf_sock_addr *ctx)
{
    struct audit_config *cfg = get_config();
    if (!cfg)
        return 1;
    __u64 run = current_run(cfg);
    if (run == 0)
        return 1;
    struct addr ip;
    ip.a[0] = ctx->user_ip6[0];
    ip.a[1] = ctx->user_ip6[1];
    ip.a[2] = ctx->user_ip6[2];
    ip.a[3] = ctx->user_ip6[3];
    __u16 port = (__u16)ctx->user_port;
    __u16 to;
    __u32 v = decide(ctx, cfg, run, &ip, port, &to);
    /* An IPv4-mapped destination is reported as IPv4. */
    emit_connect(ctx, is_v4mapped(&ip) ? AF_INET : AF_INET6, &ip, port, v);
    return rewrite6(ctx, &ip, port, v, to);
}

/* Unconnected UDP: the same decision, without an event per datagram. A
 * refusal is reported the first time each socket meets one. */
static __always_inline void report_udp_once(struct bpf_sock_addr *ctx, __u16 family, struct addr *ip, __u16 port, __u32 v)
{
    if (v != V_UDP_DENY && v != V_AUDIT_UDP)
        return;
    __u32 *seen = bpf_sk_storage_get(&udp_reported, ctx->sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (!seen || *seen)
        return;
    *seen = 1;
    emit_connect(ctx, family, ip, port, v);
}

SEC("cgroup/sendmsg4")
int on_sendmsg4(struct bpf_sock_addr *ctx)
{
    struct audit_config *cfg = get_config();
    if (!cfg)
        return 1;
    __u64 run = current_run(cfg);
    if (run == 0)
        return 1;
    struct addr ip;
    v4mapped(&ip, ctx->user_ip4);
    __u16 port = (__u16)ctx->user_port, to;
    __u32 v = decide(ctx, cfg, run, &ip, port, &to);
    report_udp_once(ctx, AF_INET, &ip, port, v);
    return rewrite4(ctx, &ip, port, v, to);
}

SEC("cgroup/sendmsg6")
int on_sendmsg6(struct bpf_sock_addr *ctx)
{
    struct audit_config *cfg = get_config();
    if (!cfg)
        return 1;
    __u64 run = current_run(cfg);
    if (run == 0)
        return 1;
    struct addr ip;
    ip.a[0] = ctx->user_ip6[0];
    ip.a[1] = ctx->user_ip6[1];
    ip.a[2] = ctx->user_ip6[2];
    ip.a[3] = ctx->user_ip6[3];
    __u16 port = (__u16)ctx->user_port, to;
    __u32 v = decide(ctx, cfg, run, &ip, port, &to);
    report_udp_once(ctx, is_v4mapped(&ip) ? AF_INET : AF_INET6, &ip, port, v);
    return rewrite6(ctx, &ip, port, v, to);
}

/* A reply from the resolver, or the QUIC relay, appears to come from the
 * server the client asked; resolvers and QUIC clients drop replies from
 * anyone else. */
static __always_inline int redirected_port(struct audit_config *cfg, __u32 port)
{
    return (cfg->dns_port != 0 && port == bpf_htons(cfg->dns_port)) ||
           (cfg->quic_port != 0 && port == bpf_htons(cfg->quic_port));
}

SEC("cgroup/recvmsg4")
int on_recvmsg4(struct bpf_sock_addr *ctx)
{
    struct audit_config *cfg = get_config();
    if (!cfg)
        return 1;
    if (ctx->user_ip4 != bpf_htonl(0x7f000001) || !redirected_port(cfg, ctx->user_port))
        return 1;
    struct orig *o = bpf_sk_storage_get(&orig_by_sk, ctx->sk, 0, 0);
    if (o && o->family == AF_INET) {
        ctx->user_ip4 = o->ip.a[3];
        ctx->user_port = o->port;
    }
    return 1;
}

SEC("cgroup/recvmsg6")
int on_recvmsg6(struct bpf_sock_addr *ctx)
{
    struct audit_config *cfg = get_config();
    if (!cfg || !redirected_port(cfg, ctx->user_port))
        return 1;
    struct orig *o = bpf_sk_storage_get(&orig_by_sk, ctx->sk, 0, 0);
    if (!o)
        return 1;
    ctx->user_ip6[0] = o->ip.a[0];
    ctx->user_ip6[1] = o->ip.a[1];
    ctx->user_ip6[2] = o->ip.a[2];
    ctx->user_ip6[3] = o->ip.a[3];
    ctx->user_port = o->port;
    return 1;
}

static __always_inline int tag_run(struct bpf_sock_addr *ctx)
{
    struct audit_config *cfg = get_config();
    if (!cfg)
        return 1;
    __u64 run = current_run(cfg);
    if (run == 0)
        return 1;
    __u64 *v = bpf_sk_storage_get(&run_by_sk, ctx->sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (v)
        *v = run;
    return 1;
}

SEC("cgroup/bind4")
int on_bind4(struct bpf_sock_addr *ctx) { return tag_run(ctx); }

SEC("cgroup/bind6")
int on_bind6(struct bpf_sock_addr *ctx) { return tag_run(ctx); }

SEC("cgroup/getpeername4")
int on_getpeername4(struct bpf_sock_addr *ctx)
{
    struct orig *o = bpf_sk_storage_get(&orig_by_sk, ctx->sk, 0, 0);
    if (o && o->family == AF_INET && ctx->user_ip4 == bpf_htonl(0x7f000001)) {
        ctx->user_ip4 = o->ip.a[3];
        ctx->user_port = o->port;
    }
    return 1;
}

SEC("cgroup/getpeername6")
int on_getpeername6(struct bpf_sock_addr *ctx)
{
    struct orig *o = bpf_sk_storage_get(&orig_by_sk, ctx->sk, 0, 0);
    if (o) {
        ctx->user_ip6[0] = o->ip.a[0];
        ctx->user_ip6[1] = o->ip.a[1];
        ctx->user_ip6[2] = o->ip.a[2];
        ctx->user_ip6[3] = o->ip.a[3];
        ctx->user_port = o->port;
    }
    return 1;
}

SEC("sockops")
int on_sockops(struct bpf_sock_ops *skops)
{
    if (skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
        return 1;
    struct bpf_sock *sk = skops->sk;
    if (!sk)
        return 1;
    struct orig *o = bpf_sk_storage_get(&orig_by_sk, sk, 0, 0);
    if (!o)
        return 1;
    __u32 family = LOAD32(skops, struct bpf_sock_ops, family);
    __u32 l4 = LOAD32(skops, struct bpf_sock_ops, local_ip4);
    __u32 l0 = LOAD32(skops, struct bpf_sock_ops, local_ip6[0]);
    __u32 l1 = LOAD32(skops, struct bpf_sock_ops, local_ip6[1]);
    __u32 l2 = LOAD32(skops, struct bpf_sock_ops, local_ip6[2]);
    __u32 l3 = LOAD32(skops, struct bpf_sock_ops, local_ip6[3]);
    __u32 lport = LOAD32(skops, struct bpf_sock_ops, local_port); /* host order */
    struct tuple_key k = {};
    if (family == AF_INET) {
        v4mapped(&k.ip, l4);
    } else {
        k.ip.a[0] = l0;
        k.ip.a[1] = l1;
        k.ip.a[2] = l2;
        k.ip.a[3] = l3;
    }
    k.port = bpf_htons((__u16)lport);
    struct orig v = *o;
    bpf_map_update_elem(&orig_by_tuple, &k, &v, BPF_ANY);
    return 1;
}

struct sockaddr_in_ {
    __u16 family;
    __u16 port;
    __u32 addr;
    __u8  zero[8];
};

struct sockaddr_in6_ {
    __u16 family;
    __u16 port;
    __u32 flowinfo;
    __u32 addr[4];
    __u32 scope_id;
};

#define SOL_IP_         0
#define SOL_IPV6_       41
#define SO_ORIGINAL_DST 80 /* also IP6T_SO_ORIGINAL_DST */

/* On the cgroup root: answers the proxy's SO_ORIGINAL_DST. Runs never get
 * an answer, so they cannot read another run's destinations. */
SEC("cgroup/getsockopt")
int on_getsockopt(struct bpf_sockopt *ctx)
{
    if (ctx->optname != SO_ORIGINAL_DST || (ctx->level != SOL_IP_ && ctx->level != SOL_IPV6_))
        return 1;
    struct audit_config *cfg = get_config();
    if (!cfg || bpf_get_current_ancestor_cgroup_id(cfg->agents_level) == cfg->agents_cgroup_id)
        return 1;
    struct bpf_sock *sk = ctx->sk;
    if (!sk)
        return 1;

    __u32 family = LOAD32(sk, struct bpf_sock, family);
    __u32 d4 = LOAD32(sk, struct bpf_sock, dst_ip4);
    __u32 d0 = LOAD32(sk, struct bpf_sock, dst_ip6[0]);
    __u32 d1 = LOAD32(sk, struct bpf_sock, dst_ip6[1]);
    __u32 d2 = LOAD32(sk, struct bpf_sock, dst_ip6[2]);
    __u32 d3 = LOAD32(sk, struct bpf_sock, dst_ip6[3]);
    __u32 dport = LOAD32(sk, struct bpf_sock, dst_port); /* network order, low 16 bits */
    struct tuple_key k = {};
    if (family == AF_INET) {
        v4mapped(&k.ip, d4);
    } else {
        k.ip.a[0] = d0;
        k.ip.a[1] = d1;
        k.ip.a[2] = d2;
        k.ip.a[3] = d3;
    }
    k.port = (__u16)dport;
    struct orig *o = bpf_map_lookup_elem(&orig_by_tuple, &k);
    if (!o)
        return 1;

    void *start = ctx->optval, *end = ctx->optval_end;
    if (ctx->level == SOL_IP_) {
        struct sockaddr_in_ *sa = start;
        if ((void *)(sa + 1) > end || o->family != AF_INET)
            return 1;
        sa->family = AF_INET;
        sa->port = o->port;
        sa->addr = o->ip.a[3];
        __builtin_memset(sa->zero, 0, sizeof(sa->zero));
        ctx->optlen = sizeof(*sa);
    } else {
        struct sockaddr_in6_ *sa = start;
        if ((void *)(sa + 1) > end)
            return 1;
        sa->family = AF_INET6;
        sa->port = o->port;
        sa->flowinfo = 0;
        sa->addr[0] = o->ip.a[0];
        sa->addr[1] = o->ip.a[1];
        sa->addr[2] = o->ip.a[2];
        sa->addr[3] = o->ip.a[3];
        sa->scope_id = 0;
        ctx->optlen = sizeof(*sa);
    }
    ctx->retval = 0;
    return 1;
}

static __always_inline int backstop_exception(struct audit_config *cfg, struct addr *ip, __u16 hport, __u8 proto)
{
    if (proto == IPPROTO_UDP)
        return in_exceptions(cfg->udp_exc, ip, hport);
    if (proto == IPPROTO_TCP_)
        return in_exceptions(cfg->exc, ip, hport);
    return 0;
}

SEC("cgroup_skb/egress")
int on_egress(struct __sk_buff *skb)
{
    struct audit_config *cfg = get_config();
    if (!cfg || cfg->mode != MODE_ENFORCE)
        return 1;
    __u64 run = bpf_skb_ancestor_cgroup_id(skb, cfg->agents_level + 1);
    if (run == 0 || bpf_skb_ancestor_cgroup_id(skb, cfg->agents_level) != cfg->agents_cgroup_id)
        return 1;

    struct addr ip = {};
    __u8 proto;
    __u32 l4off;
    __u16 family;
    if (skb->protocol == bpf_htons(ETH_P_IP)) {
        __u8 vihl;
        __u32 d4;
        if (bpf_skb_load_bytes(skb, 0, &vihl, 1) < 0 || bpf_skb_load_bytes(skb, 9, &proto, 1) < 0 ||
            bpf_skb_load_bytes(skb, 16, &d4, 4) < 0)
            return 1;
        v4mapped(&ip, d4);
        l4off = (vihl & 0x0f) * 4;
        family = AF_INET;
    } else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
        if (bpf_skb_load_bytes(skb, 6, &proto, 1) < 0 || bpf_skb_load_bytes(skb, 24, ip.a, 16) < 0)
            return 1;
        l4off = 40; /* extension headers: no port, so no exception matches */
        family = AF_INET6;
    } else {
        return 1;
    }
    if (is_loopback(&ip))
        return 1;
    __u16 dport = 0;
    if (proto == IPPROTO_UDP || proto == IPPROTO_TCP_) {
        __u16 p;
        if (bpf_skb_load_bytes(skb, l4off + 2, &p, 2) == 0)
            dport = bpf_ntohs(p);
    }
    if (backstop_exception(cfg, &ip, dport, proto))
        return 1;
    if (proto == IPPROTO_UDP || proto == IPPROTO_ICMP_ || proto == IPPROTO_ICMPV6_) {
        __u64 prun = skb_policy_run(skb, cfg, run);
        struct net_policy *np = bpf_map_lookup_elem(&run_net, &prun);
        if (proto == IPPROTO_UDP && run_udp_ok(np, &ip, dport))
            return 1;
        if (proto != IPPROTO_UDP) {
            __u8 t;
            int echo = bpf_skb_load_bytes(skb, l4off, &t, 1) == 0 &&
                       ((proto == IPPROTO_ICMP_ && family == AF_INET && t == ICMP_ECHO_) ||
                        (proto == IPPROTO_ICMPV6_ && family == AF_INET6 && t == ICMPV6_ECHO_));
            if (echo && run_icmp_ok(np, &ip))
                return 1;
        }
    }

    int enforce = 1;
    __u64 now = bpf_ktime_get_ns();
    struct drop_state *ds = bpf_map_lookup_elem(&drop_rate, &run);
    if (!ds) {
        struct drop_state fresh = {};
        bpf_map_update_elem(&drop_rate, &run, &fresh, BPF_NOEXIST);
        ds = bpf_map_lookup_elem(&drop_rate, &run);
        if (!ds)
            return !enforce;
    }
    __sync_fetch_and_add(&ds->count, 1);
    if (now - ds->last_ns < 1000000000ULL)
        return !enforce;
    ds->last_ns = now;
    __u32 count = __sync_lock_test_and_set(&ds->count, 0);

    struct drop_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        note_lost(run);
        return !enforce;
    }
    e->hdr.type = EVENT_DROP;
    e->hdr.pid = 0;
    e->hdr.timestamp_ns = bpf_ktime_get_boot_ns();
    e->hdr.cgroup_id = bpf_skb_cgroup_id(skb);
    e->hdr.run_cgroup_id = run;
    e->family = family;
    e->dport = dport;
    e->protocol = proto;
    __builtin_memset(e->daddr, 0, sizeof(e->daddr));
    if (family == AF_INET)
        __builtin_memcpy(e->daddr, &ip.a[3], 4);
    else
        __builtin_memcpy(e->daddr, ip.a, 16);
    e->count = count;
    e->enforced = enforce;
    bpf_ringbuf_submit(e, 0);
    return !enforce;
}

/*
 * Egress bytes (milestone 5.2), counted per run in every mode: what a run
 * sends to other hosts, and on loopback to the proxy, the MCP gateway, the
 * transparent listener and the resolver (the way out of the node).
 * Loopback within the node is not counted. A nested run's bytes are also
 * charged to each run it is nested in. The node agent creates an entry
 * per run; a non-zero limit drops the packets of a run over it, or of a
 * run nested in one, and the node agent revokes its egress.
 */
struct run_bytes_val {
    __u64 used;           /* bytes sent */
    __u64 limit;          /* 0: no limit */
    __u64 dropped;        /* bytes refused at the limit */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct run_bytes_val);
} run_bytes SEC(".maps");

/* A packet that would take a run past its limit is refused, and counted
 * as dropped for that run; one that would not is charged. */
static __always_inline int bytes_over(__u64 id, __u64 len)
{
    struct run_bytes_val *v = bpf_map_lookup_elem(&run_bytes, &id);
    if (!v || v->limit == 0 || v->used + len <= v->limit)
        return 0;
    __sync_fetch_and_add(&v->dropped, len);
    return 1;
}

static __always_inline void charge_bytes(__u64 id, __u64 len)
{
    struct run_bytes_val *v = bpf_map_lookup_elem(&run_bytes, &id);
    if (v)
        __sync_fetch_and_add(&v->used, len);
}

SEC("cgroup_skb/egress")
int on_egress_count(struct __sk_buff *skb)
{
    struct audit_config *cfg = get_config();
    if (!cfg || cfg->agents_cgroup_id == 0)
        return 1;
    if (bpf_skb_ancestor_cgroup_id(skb, cfg->agents_level) != cfg->agents_cgroup_id)
        return 1;
    __u64 run = bpf_skb_ancestor_cgroup_id(skb, cfg->agents_level + 1);
    if (run == 0)
        return 1;

    struct addr ip = {};
    __u8 proto;
    __u32 l4off;
    if (skb->protocol == bpf_htons(ETH_P_IP)) {
        __u8 vihl;
        __u32 d4;
        if (bpf_skb_load_bytes(skb, 0, &vihl, 1) < 0 || bpf_skb_load_bytes(skb, 9, &proto, 1) < 0 ||
            bpf_skb_load_bytes(skb, 16, &d4, 4) < 0)
            return 1;
        v4mapped(&ip, d4);
        l4off = (vihl & 0x0f) * 4;
    } else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
        if (bpf_skb_load_bytes(skb, 6, &proto, 1) < 0 || bpf_skb_load_bytes(skb, 24, ip.a, 16) < 0)
            return 1;
        l4off = 40;
    } else {
        return 1;
    }
    if (is_loopback(&ip)) {
        __u16 dport = 0;
        if (proto == IPPROTO_UDP || proto == IPPROTO_TCP_) {
            __u16 p;
            if (bpf_skb_load_bytes(skb, l4off + 2, &p, 2) == 0)
                dport = bpf_ntohs(p);
        }
        if (dport == 0 || !(in_exceptions(cfg->exc, &ip, dport) || dport == cfg->tproxy_port ||
                            (cfg->dns_port != 0 && dport == cfg->dns_port) ||
                            (cfg->quic_port != 0 && dport == cfg->quic_port)))
            return 1;
    }

    /* The packet's run and each run it is nested in, innermost last. */
    __u64 len = skb->len;
    __u64 ids[MAX_NEST + 1] = {run};
#pragma unroll
    for (int i = 1; i <= MAX_NEST; i++) {
        __u64 id = bpf_skb_ancestor_cgroup_id(skb, cfg->agents_level + 1 + i);
        ids[i] = id && bpf_map_lookup_elem(&nested_run, &id) ? id : 0;
    }
    int over = 0;
#pragma unroll
    for (int i = 0; i <= MAX_NEST; i++)
        if (ids[i])
            over |= bytes_over(ids[i], len);
    if (over)
        return 0;
#pragma unroll
    for (int i = 0; i <= MAX_NEST; i++)
        if (ids[i])
            charge_bytes(ids[i], len);
    return 1;
}

/*
 * The proxy's own connects (milestone 3.5), attached to Envoy's cgroup
 * when it holds nothing else. ext_proc refuses node-local destinations,
 * but checks a name by resolving it itself: a name that resolves
 * differently for Envoy a moment later (DNS rebinding) would still reach
 * the node. Here the kernel refuses the connect itself. DNS (port 53) is
 * let through: Envoy's resolver may be on loopback.
 */
static __always_inline int node_local(struct addr *ip)
{
    if (is_v4mapped(ip)) {
        __u32 a = bpf_ntohl(ip->a[3]);
        return (a >> 24) == 127 || (a >> 16) == 0xa9fe /* 169.254/16 */ ||
               a == 0 || (a >> 28) == 0xe /* multicast */;
    }
    __u32 w0 = bpf_ntohl(ip->a[0]);
    if (ip->a[0] == 0 && ip->a[1] == 0 && ip->a[2] == 0 && (ip->a[3] == 0 || ip->a[3] == bpf_htonl(1)))
        return 1; /* :: and ::1 */
    return (w0 >> 22) == (0xfe80 >> 6) /* fe80::/10 */ || (w0 >> 24) == 0xff /* multicast */;
}

/* Connects the gate refused, for the node agent to report. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} proxy_refused SEC(".maps");

static __always_inline int proxy_gate(struct addr *ip, __u16 port)
{
    if (bpf_ntohs(port) == 53 || !node_local(ip))
        return 1;
    __u32 zero = 0;
    __u64 *n = bpf_map_lookup_elem(&proxy_refused, &zero);
    if (n)
        __sync_fetch_and_add(n, 1);
    return 0;
}

SEC("cgroup/connect4")
int on_proxy_connect4(struct bpf_sock_addr *ctx)
{
    struct addr ip;
    v4mapped(&ip, ctx->user_ip4);
    return proxy_gate(&ip, (__u16)ctx->user_port);
}

SEC("cgroup/connect6")
int on_proxy_connect6(struct bpf_sock_addr *ctx)
{
    struct addr ip;
    ip.a[0] = ctx->user_ip6[0];
    ip.a[1] = ctx->user_ip6[1];
    ip.a[2] = ctx->user_ip6[2];
    ip.a[3] = ctx->user_ip6[3];
    return proxy_gate(&ip, (__u16)ctx->user_port);
}

/* ---- BPF LSM (milestones 4.1 and 4.3) ---- */

#define EPERM_ 1
#define AF_UNIX_    1
#define AF_NETLINK_ 16
#define SOCK_RAW_    3
#define SOCK_PACKET_ 10

/* An LSM program passes on an earlier program's refusal, bounded as the
 * verifier requires. */
static __always_inline int lsm_prev(long ret)
{
    return ret < 0 && ret >= -4095 ? (int)ret : -EPERM_;
}

/* The id of cg's ancestor at level (cg itself at its own level), or 0. */
static __always_inline __u64 cgroup_ancestor_id(struct cgroup *cg, __u32 level)
{
    if (!cg)
        return 0;
    int l = BPF_CORE_READ(cg, level);
    if ((int)level > l || level > 63)
        return 0;
    if (bpf_core_field_exists(struct cgroup___ptrs, ancestors)) {
        struct cgroup___ptrs *c = (void *)cg;
        struct cgroup *a = 0;
        if (bpf_core_read(&a, sizeof(a), &c->ancestors[level & 63]) < 0 || !a)
            return 0;
        return BPF_CORE_READ(a, kn, id);
    }
    struct cgroup___ids *c = (void *)cg;
    __u64 id = 0;
    bpf_core_read(&id, sizeof(id), &c->ancestor_ids[level & 63]);
    return id;
}

static __always_inline void emit_socket(struct audit_config *cfg, __u64 run, __u16 family, __u16 type,
                                        __u32 protocol, __u32 op, __u32 verdict, __u64 sk_cg)
{
    struct event_hdr hdr = {};
    if (!fill_hdr(&hdr, EVENT_SOCKET))
        return;
    if (!within_budget(hdr.run_cgroup_id, sizeof(struct socket_event)))
        return;
    struct socket_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        note_lost(hdr.run_cgroup_id);
        return;
    }
    e->hdr = hdr;
    e->family = family;
    e->type = type;
    e->protocol = protocol;
    e->op = op;
    e->verdict = verdict;
    e->sk_cgroup = sk_cg;
    bpf_ringbuf_submit(e, 0);
}

/* security_socket_create(int family, int type, int protocol, int kern) */
SEC("lsm/socket_create")
int on_lsm_socket_create(__u64 *ctx)
{
    int family = (int)ctx[0], type = (int)ctx[1], protocol = (int)ctx[2], kern = (int)ctx[3];
    long ret = (long)(int)ctx[4];
    if (ret)
        return lsm_prev(ret);
    if (kern)
        return 0;
    struct audit_config *cfg = get_config();
    if (!cfg || cfg->mode == MODE_OFF)
        return 0;
    __u64 run = current_run(cfg);
    if (run == 0)
        return 0;
    int inet = family == AF_INET || family == AF_INET6;
    int ok = (inet || family == AF_UNIX_ || family == AF_NETLINK_) &&
             !(inet && (type == SOCK_RAW_ || type == SOCK_PACKET_));
    if (ok)
        return 0;
    int enforce = cfg->mode == MODE_ENFORCE;
    emit_socket(cfg, run, family, type, protocol, SOCK_OP_CREATE, enforce ? V_SOCK_DENY : V_AUDIT_SOCK, 0);
    return enforce ? -EPERM_ : 0;
}

/* A network socket used by a task in a run must have been created in that
 * run; otherwise its traffic skipped every cgroup hook. */
static __always_inline int foreign_socket(struct socket *sock, __u32 op)
{
    struct audit_config *cfg = get_config();
    if (!cfg || cfg->mode == MODE_OFF)
        return 0;
    __u64 run = current_run(cfg);
    if (run == 0)
        return 0;
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return 0; /* Unix sockets: milestone 4.2 */
    struct cgroup *cg = BPF_CORE_READ(sk, sk_cgrp_data.cgroup);
    if (cgroup_ancestor_id(cg, cfg->agents_level + 1) == run)
        return 0;
    int enforce = cfg->mode == MODE_ENFORCE;
    __u64 sk_cg = cg ? BPF_CORE_READ(cg, kn, id) : 0;
    emit_socket(cfg, run, family, 0, 0, op, enforce ? V_SOCK_DENY : V_AUDIT_SOCK, sk_cg);
    return enforce ? -EPERM_ : 0;
}

/* ---- Exec (milestone 4.4) ---- */

#define EXEC_PATH      256
#define EXEC_WORDS     32
#define MAX_EXEC_LAYERS   6
#define MAX_EXEC_PREFIXES 4
#define TRUST_DEPTH    24

struct exec_prefix {
    __u16 len;
    __u8  _pad[6];
    __u64 b[EXEC_WORDS];
    __u64 m[EXEC_WORDS];  /* mask over len bytes, from the node agent */
};

struct exec_layer {
    __u32 default_allow;
    __u32 require_trusted;
    __u32 enforce;        /* an enforcing layer refuses; an audit layer reports */
    __u32 n_prefix;
    struct exec_prefix pre[MAX_EXEC_PREFIXES];
};

struct exec_policy {
    __u32 n;
    __u32 _pad;
    struct exec_layer l[MAX_EXEC_LAYERS];
};

/* Per run: its exec layers. Absent: no exec policy (nothing refused). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u64);
    __type(value, struct exec_policy);
} exec_policy SEC(".maps");

struct exec_key {
    __u64 run;
    __u32 layer;
    __u32 _pad;
    __u64 hash;
};

struct exec_path {
    __u64 b[EXEC_WORDS];
};

#define MAX_EXEC_HASHES 4
#define SHA256_LEN      32

/* An exact exec.allow entry: the path, and the SHA-256s its content may
 * have (milestone 5.7). */
struct exec_allowed {
    __u64 b[EXEC_WORDS];
    __u32 n_hash;         /* 0: the path alone passes */
    __u32 _pad;
    __u64 sha[MAX_EXEC_HASHES][SHA256_LEN / 8]; /* the digest's bytes, as words */
};

/* Exact exec.allow paths, per run and layer, by hash; the value holds the
 * path, compared in full so a crafted collision gains nothing. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct exec_key);
    __type(value, struct exec_allowed);
} exec_allow SEC(".maps");

/* Per run, the resolved paths already reported (with their verdict). */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct exec_key);
    __type(value, __u8);
} exec_seen SEC(".maps");

/* exec_path_event flags (milestone 5.7) */
#define EXEC_HASHED   1 /* sha is the file's SHA-256 */
#define EXEC_CACHED   2 /* from exec_sums, not computed for this exec */
#define EXEC_MISMATCH 4 /* an entry with hashes named the path; the content is none of them */
#define EXEC_HASH_ERR 8 /* the file could not be hashed */

struct exec_path_event {
    struct event_hdr hdr;
    __u8  path[EXEC_PATH];
    __u32 len;
    __u32 verdict;        /* V_EXEC_* */
    __u32 trusted;
    __u32 flags;
    __u8  sha[SHA256_LEN];
};

/* The exec hash cache (milestone 5.7; 5.0 spike): a file's SHA-256 by
 * (device, inode), with the kernel's validators as they were when it was
 * hashed. Shared by every run: it holds content hashes, not decisions. */
struct exec_ino {
    __u64 dev;
    __u64 ino;
};

struct exec_sum {
    __s64 version;        /* i_version, less its queried flag */
    __s64 ctime_sec;
    __u32 ctime_nsec;     /* less the multigrain queried flag */
    __u32 gen;
    __u8  sha[SHA256_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct exec_ino);
    __type(value, struct exec_sum);
} exec_sums SEC(".maps");

/* Scratch for one exec: the resolved path, too large for the stack beside
 * the rest, and the file's hash. Per task, not per CPU: the hook sleeps
 * while it hashes, and another exec on the same CPU could overwrite
 * per-CPU scratch meanwhile. Keeping the hash's outcome here rather than
 * in registers also keeps the verifier from walking the layers once per
 * outcome. */
struct exec_task {
    struct exec_path p;
    struct exec_sum sum;
    __u64 h;              /* exec_hash of p */
    __u32 len;            /* of p */
    __u32 trusted;        /* trusted_path */
    __u32 flags;          /* EXEC_* */
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct exec_task);
} exec_scratch SEC(".maps");

#define HASH_ALGO_SHA256_ 4          /* enum hash_algo */
#define SB_I_VERSION_     (1UL << 23)
#define EXT4_MAGIC_       0xEF53
#define XFS_MAGIC_        0x58465342
#define BTRFS_MAGIC_      0x9123683E
#define TMPFS_MAGIC_      0x01021994
/* A file is cached only once its change time is this many seconds old by
 * the TAI clock (ahead of real time by at most 37 s), so a later write in
 * the same clock tick cannot leave the change time as it was. */
#define EXEC_SUM_SETTLED  60

static __always_inline int trusted_inode(struct inode *ino)
{
    if (!ino)
        return 0;
    return BPF_CORE_READ(ino, i_uid.val) == 0 && !(BPF_CORE_READ(ino, i_mode) & 0022);
}

/* The file and every directory up to the root, across mounts, owned by
 * root and not writable by group or others: nothing but root could have
 * put this file here (4.0 spike). */
static __always_inline int trusted_path(struct file *f)
{
    if (!trusted_inode(BPF_CORE_READ(f, f_inode)))
        return 0;
    struct vfsmount *vmnt = BPF_CORE_READ(f, f_path.mnt);
    struct mount *m = (void *)vmnt - bpf_core_field_offset(struct mount, mnt);
    struct dentry *d = BPF_CORE_READ(f, f_path.dentry, d_parent);
    for (int i = 0; i < TRUST_DEPTH; i++) {
        struct dentry *mroot = BPF_CORE_READ(m, mnt.mnt_root);
        if (d == mroot) {
            struct mount *parent = BPF_CORE_READ(m, mnt_parent);
            if (parent == m)
                return trusted_inode(BPF_CORE_READ(d, d_inode)); /* the global root */
            d = BPF_CORE_READ(m, mnt_mountpoint);
            m = parent;
            continue;
        }
        if (!trusted_inode(BPF_CORE_READ(d, d_inode)))
            return 0;
        d = BPF_CORE_READ(d, d_parent);
    }
    return 0; /* deeper than TRUST_DEPTH: not shown trusted */
}

/* Zero p past len bytes. bpf_d_path builds the path at the end of the
 * buffer and moves it to the front, so what follows the NUL is the end of
 * the path again; exact entries are hashed and compared over all of it.
 * Arithmetic, not branches, as len is not known to the verifier. */
static __always_inline void exec_clear_tail(struct exec_path *p, __u32 len)
{
#pragma unroll
    for (int j = 0; j < EXEC_WORDS; j++) {
        __s64 s = (__s64)len - 8 * j;    /* bytes of this word to keep */
        __u64 full = (__u64)(7 - s) >> 63; /* s >= 8 */
        __u64 some = (__u64)(0 - s) >> 63; /* s > 0 */
        asm volatile("" : "+r"(full), "+r"(some));
        __u64 part = (1ULL << (8 * (s & 7))) - 1;
        p->b[j] &= (0 - full) | ((0 - (some & (full ^ 1))) & part);
    }
}

static __always_inline __u64 exec_hash(struct exec_path *p)
{
    __u64 h = 14695981039346656037ULL;
#pragma unroll
    for (int j = 0; j < EXEC_WORDS; j++)
        h = (h ^ p->b[j]) * 1099511628211ULL;
    return h;
}

/* 1: listed; 2: an exact entry with hashes names it, so its content
 * decides; 0: not listed. */
static __always_inline int exec_listed(__u64 run, __u32 layer, struct exec_layer *l, struct exec_path *p, __u64 h, __u32 len)
{
    struct exec_key k = {.run = run, .layer = layer, .hash = h};
    struct exec_allowed *v = bpf_map_lookup_elem(&exec_allow, &k);
    if (v) {
        __u64 diff = 0;
#pragma unroll
        for (int j = 0; j < EXEC_WORDS; j++)
            diff |= v->b[j] ^ p->b[j];
        if (diff == 0)
            return v->n_hash ? 2 : 1;
    }
    __u32 n = l->n_prefix;
#pragma unroll
    for (int i = 0; i < MAX_EXEC_PREFIXES; i++) {
        struct exec_prefix *x = &l->pre[i];
        __u64 diff = 0;
#pragma unroll
        for (int j = 0; j < EXEC_WORDS; j++)
            diff |= (p->b[j] ^ x->b[j]) & x->m[j];
        if ((__u32)i < n && x->len <= len && diff == 0)
            return 1;
    }
    return 0;
}

/* 1 if x is 0, else 0; and 1 if a < b, else 0. Arithmetic, not branches:
 * the verifier would follow every combination of branched results. The
 * barrier keeps the compiler from turning them back into compares. */
static __always_inline __u64 bf_zero(__u64 x)
{
    __u64 neg = -x;
    asm volatile("" : "+r"(neg));
    return ((x | neg) >> 63) ^ 1;
}

static __always_inline __u64 bf_lt(__u32 a, __u32 b)
{
    __u64 d = (__u64)a - (__u64)b;
    asm volatile("" : "+r"(d));
    return d >> 63;
}

/* Whether some layer below n has an exact entry with hashes under this
 * path's hash. The path itself is compared when layers decide: a
 * colliding path costs a needless hash, nothing more. */
static __always_inline int exec_pinned(__u64 run, __u32 n, __u64 h)
{
    struct exec_key k = {.run = run, .hash = h};
    __u64 pinned = 0;
#pragma unroll
    for (int i = 0; i < MAX_EXEC_LAYERS; i++) {
        k.layer = i;
        struct exec_allowed *v = bpf_map_lookup_elem(&exec_allow, &k);
        if (v)
            pinned |= bf_lt(i, n) & (bf_zero(v->n_hash) ^ 1);
    }
    return pinned;
}

/* Whether layer's exact entry for this path (already compared) lists sha. */
static __always_inline int exec_sha_listed(__u64 run, __u32 layer, __u64 h, __u8 *sha)
{
    struct exec_key k = {.run = run, .layer = layer, .hash = h};
    struct exec_allowed *v = bpf_map_lookup_elem(&exec_allow, &k);
    if (!v)
        return 0;
    __u64 w[SHA256_LEN / 8];
    __builtin_memcpy(w, sha, SHA256_LEN);
    __u32 n = v->n_hash;
    __u64 found = 0;
#pragma unroll
    for (int i = 0; i < MAX_EXEC_HASHES; i++) {
        __u64 diff = (v->sha[i][0] ^ w[0]) | (v->sha[i][1] ^ w[1]) | (v->sha[i][2] ^ w[2]) | (v->sha[i][3] ^ w[3]);
        found |= bf_lt(i, n) & bf_zero(diff);
    }
    return found;
}

/* The inode's cache key and validators. Nonzero if a cached hash can be
 * trusted for it: a local filesystem that keeps i_version (FUSE and
 * network filesystems can change content behind an unchanged inode), and
 * no one has the file open for writing. */
static __always_inline int exec_validators(struct inode *in, struct exec_ino *k, struct exec_sum *s)
{
    struct super_block *sb = BPF_CORE_READ(in, i_sb);
    unsigned long magic = BPF_CORE_READ(sb, s_magic);
    unsigned long flags = BPF_CORE_READ(sb, s_flags);
    k->dev = BPF_CORE_READ(sb, s_dev);
    k->ino = BPF_CORE_READ(in, i_ino);
    s->version = BPF_CORE_READ(in, i_version.counter) >> 1;
    s->gen = BPF_CORE_READ(in, i_generation);
    if (bpf_core_field_exists(in->i_ctime_sec)) {
        s->ctime_sec = BPF_CORE_READ(in, i_ctime_sec);
        s->ctime_nsec = BPF_CORE_READ(in, i_ctime_nsec) & 0x7fffffff;
    } else {
        struct inode___ctime *o = (void *)in;
        s->ctime_sec = BPF_CORE_READ(o, __i_ctime.tv_sec);
        s->ctime_nsec = BPF_CORE_READ(o, __i_ctime.tv_nsec) & 0x7fffffff;
    }
    int local = magic == EXT4_MAGIC_ || magic == XFS_MAGIC_ || magic == BTRFS_MAGIC_ || magic == TMPFS_MAGIC_;
    return local && (flags & SB_I_VERSION_) && BPF_CORE_READ(in, i_writecount.counter) <= 0;
}

/* The file's SHA-256 into s->sha, from the cache or bpf_ima_file_hash,
 * which sleeps. Exec holds off writers until it completes, so the content
 * cannot change while it is hashed. Returns EXEC_* flags. */
static __always_inline __u32 exec_file_sha(struct file *f, struct exec_sum *s)
{
    struct inode *in = BPF_CORE_READ(f, f_inode);
    struct exec_ino k = {};
    int cacheable = exec_validators(in, &k, s);
    if (cacheable) {
        struct exec_sum *v = bpf_map_lookup_elem(&exec_sums, &k);
        if (v && v->version == s->version && v->ctime_sec == s->ctime_sec &&
            v->ctime_nsec == s->ctime_nsec && v->gen == s->gen) {
            __builtin_memcpy(s->sha, v->sha, SHA256_LEN);
            return EXEC_HASHED | EXEC_CACHED;
        }
    }
    if (bpf_ima_file_hash(f, s->sha, SHA256_LEN) != HASH_ALGO_SHA256_)
        return EXEC_HASH_ERR;
    __s64 now = bpf_ktime_get_tai_ns() / 1000000000ULL;
    if (cacheable && s->ctime_sec + EXEC_SUM_SETTLED < now)
        bpf_map_update_elem(&exec_sums, &k, s, BPF_ANY);
    return EXEC_HASHED;
}

/* Whether layer i passes the exec in t. A global function, so the
 * verifier checks the matching once, not once per layer for each way the
 * caller reached it (which is more states than it allows). */
__attribute__((noinline)) int exec_layer_ok(struct exec_policy *pol, struct exec_task *t, __u64 run, __u32 i, int hashing)
{
    if (!pol || !t || i >= MAX_EXEC_LAYERS)
        return 0;
    struct exec_layer *l = &pol->l[i];
    int r = exec_listed(run, i, l, &t->p, t->h, t->len);
    if (r == 2) {
        int ok = hashing && (t->flags & EXEC_HASHED) && exec_sha_listed(run, i, t->h, t->sum.sha);
        if (!ok && (t->flags & EXEC_HASHED))
            t->flags |= EXEC_MISMATCH;
        return ok;
    }
    if (r == 1)
        return 1;
    if (l->require_trusted && !t->trusted)
        return 0;
    return l->default_allow != 0;
}

/* Report an exec's resolved path, once per run, verdict and content
 * (where it was hashed), and once more when the cache first answers for
 * it: what learn and check need, without an event per exec of a hot
 * binary. A global function, so its locals are not on exec_check's frame
 * with exec_layer_ok's: kernels before 7.0 counted the two over 512
 * bytes (7.2). */
__attribute__((noinline)) int exec_report(struct exec_task *t, __u64 run, __u32 verdict)
{
    if (!t)
        return 0;
    __u64 seen = t->h;
    if (t->flags & EXEC_HASHED) {
        __u64 x;
        __builtin_memcpy(&x, t->sum.sha, sizeof(x));
        seen ^= x ^ (t->flags & EXEC_CACHED);
    }
    struct exec_key sk = {.run = run, .layer = verdict, .hash = seen};
    __u8 one = 1;
    if (bpf_map_update_elem(&exec_seen, &sk, &one, BPF_NOEXIST) != 0)
        return 0;
    struct exec_path_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        struct event_hdr hdr = {};
        if (fill_hdr(&hdr, EVENT_EXEC_PATH))
            note_lost(hdr.run_cgroup_id);
        return 0;
    }
    if (!fill_hdr(&e->hdr, EVENT_EXEC_PATH) || !within_budget(e->hdr.run_cgroup_id, sizeof(*e))) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    __builtin_memcpy(e->path, t->p.b, EXEC_PATH);
    e->len = t->len;
    e->verdict = verdict;
    e->trusted = t->trusted;
    e->flags = t->flags;
    __builtin_memcpy(e->sha, t->sum.sha, SHA256_LEN);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* The exec decision for both programs below; hashing is a constant. */
static __always_inline int exec_check(struct linux_binprm *bprm, int ret, const int hashing)
{
    if (ret)
        return lsm_prev(ret);
    struct audit_config *cfg = get_config();
    if (!cfg || cfg->mode == MODE_OFF)
        return 0;
    __u64 run = current_run(cfg);
    if (run == 0)
        return 0;
    run = policy_run(cfg, run);
    struct exec_policy *pol = bpf_map_lookup_elem(&exec_policy, &run);

    struct exec_task *t = bpf_task_storage_get(&exec_scratch, bpf_get_current_task_btf(), 0,
                                               BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!t)
        return pol && cfg->mode == MODE_ENFORCE ? -EPERM_ : 0; /* out of memory: fail closed */
    struct exec_path *p = &t->p;
    __builtin_memset(p, 0, sizeof(*p));
    t->flags = 0;
    /* Direct access keeps the pointer trusted, as bpf_d_path and
     * bpf_ima_file_hash require. */
    struct file *f = bprm->file;
    long n = bpf_d_path(&f->f_path, (char *)p->b, EXEC_PATH);
    if (n <= 0)
        return 0;
    __u32 len = n - 1; /* n counts the NUL */
    exec_clear_tail(p, len);
    int trusted = trusted_path(f);
    __u64 h = exec_hash(p);

    /* The file is hashed only if some layer's exact entry for the path
     * lists hashes. Without hashing, such an entry passes nothing. */
    if (hashing && pol && exec_pinned(run, pol->n, h)) {
        t->flags = exec_file_sha(f, &t->sum);
        pol = bpf_map_lookup_elem(&exec_policy, &run); /* again, after a sleep */
    }

    t->h = h;
    t->len = len;
    t->trusted = trusted;
    int deny = 0, refuse = 0;
    if (pol) {
        __u32 nl = pol->n;
#pragma unroll
        for (int i = 0; i < MAX_EXEC_LAYERS; i++) {
            if ((__u32)i >= nl)
                break;
            if (!exec_layer_ok(pol, t, run, i, hashing)) {
                deny = 1;
                if (pol->l[i].enforce)
                    refuse = 1;
            }
        }
    }
    refuse = refuse && cfg->mode == MODE_ENFORCE;
    __u32 verdict = refuse ? V_EXEC_DENY : (deny ? V_AUDIT_EXEC : V_EXEC_OK);

    exec_report(t, run, verdict);
    return refuse ? -EPERM_ : 0;
}

/* Exec policy with hashes (milestone 5.7): sleepable for
 * bpf_ima_file_hash (Linux 5.18) and the TAI clock (5.19). It sleeps only
 * for an exact entry with hashes whose file is not cached. */
SEC("lsm.s/bprm_check_security")
int BPF_PROG(on_lsm_exec_hash, struct linux_binprm *bprm, int ret)
{
    return exec_check(bprm, ret, 1);
}

/* Exec policy by path alone, for kernels the program above does not load
 * on; the node agent then refuses profiles with hashes. */
SEC("lsm/bprm_check_security")
int BPF_PROG(on_lsm_exec, struct linux_binprm *bprm, int ret)
{
    return exec_check(bprm, ret, 0);
}

/* ---- Unix sockets (milestone 4.2) ---- */

static __always_inline int unix_match(struct unix_policy *pol, __u64 *b, __u32 len)
{
    if (!pol)
        return 0;
    __u32 n = pol->n;
#pragma unroll
    for (int i = 0; i < MAX_UNIX_PATTERNS; i++) {
        struct unix_pat *p = &pol->p[i];
        __u64 diff = 0;
#pragma unroll
        for (int j = 0; j < UNIX_WORDS; j++)
            diff |= (b[j] ^ p->b[j]) & p->m[j];
        __u32 plen = p->len;
        int len_ok = p->prefix ? plen <= len : plen == len;
        if ((__u32)i < n && len_ok && diff == 0)
            return 1;
    }
    return 0;
}

static __always_inline int unix_decide(struct sock *peer, __u32 dgram)
{
    struct audit_config *cfg = get_config();
    if (!cfg || cfg->mode == MODE_OFF || !peer)
        return 0;
    __u64 run = current_run(cfg);
    if (run == 0)
        return 0;
    struct cgroup *pcg = BPF_CORE_READ(peer, sk_cgrp_data.cgroup);
    if (cgroup_ancestor_id(pcg, cfg->agents_level + 1) == run)
        return 0; /* the run's own socket: its tree's, nested runs included */
    run = policy_run(cfg, run);
    struct unix_address *addr = BPF_CORE_READ((struct unix_sock *)peer, addr);
    if (!addr)
        return 0; /* unbound: a socketpair or similar, handed over by its owner */

    __u64 b[UNIX_WORDS] = {};
    if (bpf_core_read(b, 108, &addr->name[0].sun_path) < 0)
        return 0;
    /* The bound length counts sun_family (2 bytes) and, for a filesystem
     * path, a trailing NUL the kernel adds. */
    int alen = BPF_CORE_READ(addr, len) - 2;
    if (alen < 0)
        alen = 0;
    if (alen > 108)
        alen = 108;
    __u8 *c = (__u8 *)b;
    __u32 len = alen;
    if (c[0] == 0) {
        c[0] = '@'; /* abstract: shown as @name */
    } else if (len > 0 && c[(len - 1) & 127] == 0) {
        len--;
    }

    __u32 zero = 0;
    if (unix_match(bpf_map_lookup_elem(&unix_node, &zero), b, len))
        return 0;
    struct unix_policy *pol = bpf_map_lookup_elem(&unix_policy, &run);
    if (unix_match(pol, b, len))
        return 0;
    int enforce = cfg->mode == MODE_ENFORCE && pol && pol->enforce;

    struct unix_seen_key k = {.run = run, .hash = 14695981039346656037ULL};
    for (int j = 0; j < UNIX_WORDS; j++)
        k.hash = (k.hash ^ b[j]) * 1099511628211ULL;
    __u8 one = 1;
    if (bpf_map_update_elem(&unix_seen, &k, &one, BPF_NOEXIST) == 0) {
        struct event_hdr hdr = {};
        if (fill_hdr(&hdr, EVENT_UNIX) && within_budget(hdr.run_cgroup_id, sizeof(struct unix_event))) {
            struct unix_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (e) {
                e->hdr = hdr;
                __builtin_memcpy(e->path, b, sizeof(e->path));
                e->len = len;
                e->verdict = enforce ? V_UNIX_DENY : V_AUDIT_UNIX;
                e->dgram = dgram;
                e->_pad = 0;
                e->peer_cgroup = pcg ? BPF_CORE_READ(pcg, kn, id) : 0;
                bpf_ringbuf_submit(e, 0);
            } else {
                note_lost(hdr.run_cgroup_id);
            }
        }
    }
    return enforce ? -EPERM_ : 0;
}

/* security_unix_stream_connect(struct sock *sock, struct sock *other, struct sock *newsk) */
SEC("lsm/unix_stream_connect")
int on_lsm_unix_stream_connect(__u64 *ctx)
{
    long ret = (long)(int)ctx[3];
    if (ret)
        return lsm_prev(ret);
    return unix_decide((struct sock *)ctx[1], 0);
}

/* security_unix_may_send(struct socket *sock, struct socket *other) */
SEC("lsm/unix_may_send")
int on_lsm_unix_may_send(__u64 *ctx)
{
    long ret = (long)(int)ctx[2];
    if (ret)
        return lsm_prev(ret);
    struct socket *other = (struct socket *)ctx[1];
    return unix_decide(BPF_CORE_READ(other, sk), 1);
}

/* security_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen) */
SEC("lsm/socket_connect")
int on_lsm_socket_connect(__u64 *ctx)
{
    long ret = (long)(int)ctx[3];
    if (ret)
        return lsm_prev(ret);
    return foreign_socket((struct socket *)ctx[0], SOCK_OP_CONNECT);
}

/* security_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size) */
SEC("lsm/socket_sendmsg")
int on_lsm_socket_sendmsg(__u64 *ctx)
{
    long ret = (long)(int)ctx[3];
    if (ret)
        return lsm_prev(ret);
    return foreign_socket((struct socket *)ctx[0], SOCK_OP_SEND);
}

/* ---- TLS plaintext (milestone 6.2) ----
 *
 * For runs whose profile asks (observe.tls_plaintext) on nodes with
 * -uprobes. Uprobes on a shared library trap in every process that maps
 * it (6.0), so the node agent attaches them per process: on_tls_exec
 * reports each exec in such a run, and while the node agent is alive
 * stops the process (SIGSTOP) until its probes are attached and it is
 * continued. The node agent also continues any process held for more than
 * a second, so a lost event cannot leave one stopped. The probes copy
 * bounded plaintext; nothing here decides anything.
 */

#define TLS_CAP_WRITE 2048 /* request lines and headers, an MCP call */
#define TLS_CAP_READ  512  /* a status line or HEADERS frame */
#define SIGSTOP_ 19

/* Per policy run: capture TLS plaintext. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} tls_capture SEC(".maps");

/* Processes stopped at exec, by tgid: when (for the node agent's watchdog). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u64);
} tls_held SEC(".maps");

/* Processes with probes attached, by tgid (written by the node agent). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u8);
} tls_pids SEC(".maps");

struct tls_exec_event {
    struct event_hdr hdr;
    __u32 held;
    __u32 _pad;
};

struct tls_data_event {
    struct event_hdr hdr;
    __u32 dir;     /* 1 write, 2 read */
    __u32 lib;     /* 1 OpenSSL or BoringSSL, 2 GnuTLS, 3 Go crypto/tls, 4 OpenSSL linked in */
    __u64 obj;     /* SSL *, gnutls_session_t or *tls.Conn: the connection */
    __u32 len;     /* bytes the call wrote or read */
    __u32 caplen;
    __u8  data[TLS_CAP_WRITE];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tls_data_event);
} tls_scratch SEC(".maps");

struct tls_stash {
    __u64 obj;
    __u64 buf;
    __u64 extra; /* the _ex forms: where the byte count is stored */
};

/* By pid_tgid: between a call's entry and its return. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct tls_stash);
} tls_writes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct tls_stash);
} tls_reads SEC(".maps");

SEC("tp_btf/sched_process_exec")
int on_tls_exec(__u64 *ctx)
{
    struct audit_config *cfg = get_config();
    if (!cfg)
        return 0;
    __u64 run = current_run(cfg);
    if (run == 0)
        return 0;
    __u64 prun = policy_run(cfg, run);
    if (!bpf_map_lookup_elem(&tls_capture, &prun))
        return 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    /* Reported also when the process already has probes: the library
     * probes survive exec, but a Go binary's are on the binary it left
     * (milestone 6.3). */
    struct tls_exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        note_lost(run);
        return 0; /* not stopped: no one would continue it */
    }
    if (!fill_hdr(&e->hdr, EVENT_TLS_EXEC)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    /* Stop it only while the node agent is alive to continue it. */
    __u32 held = healthy(cfg);
    e->held = held;
    e->_pad = 0;
    if (held) {
        __u64 now = bpf_ktime_get_ns();
        bpf_map_update_elem(&tls_held, &pid, &now, BPF_ANY);
    }
    bpf_ringbuf_submit(e, 0);
    if (held)
        bpf_send_signal(SIGSTOP_);
    return 0;
}

SEC("tp_btf/sched_process_exit")
int on_tls_exit(__u64 *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    if ((__u32)id != pid)
        return 0; /* a thread, not the process */
    if (bpf_map_delete_elem(&tls_pids, &pid) != 0)
        return 0;
    bpf_map_delete_elem(&tls_held, &pid);
    struct tls_exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    if (!fill_hdr(&e->hdr, EVENT_TLS_EXIT)) {
        /* Its cgroup may be gone already: report it anyway. */
        __builtin_memset(&e->hdr, 0, sizeof(e->hdr));
        e->hdr.type = EVENT_TLS_EXIT;
        e->hdr.pid = pid;
    }
    e->held = 0;
    e->_pad = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline int tls_stash_call(void *m, void *obj, const void *buf, void *extra)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct tls_stash st = {.obj = (__u64)obj, .buf = (__u64)buf, .extra = (__u64)extra};
    bpf_map_update_elem(m, &id, &st, BPF_ANY);
    return 0;
}

/* Copy n bytes of what a call wrote (dir 1) or read (dir 2), bounded,
 * to the node agent. */
static __always_inline int tls_emit(__u32 dir, __u32 lib, __u64 obj, __u64 buf, __s64 n)
{
    if (n <= 0)
        return 0;
    __u32 zero = 0;
    struct tls_data_event *e = bpf_map_lookup_elem(&tls_scratch, &zero);
    if (!e)
        return 0;
    if (!fill_hdr(&e->hdr, EVENT_TLS_DATA))
        return 0;
    __u32 cap = dir == 1 ? TLS_CAP_WRITE : TLS_CAP_READ;
    __u32 cl = n > cap ? cap : (__u32)n;
    if (cl > TLS_CAP_WRITE)
        cl = TLS_CAP_WRITE;
    e->dir = dir;
    e->lib = lib;
    e->obj = obj;
    e->len = n > 0xffffffff ? 0xffffffff : (__u32)n;
    if (bpf_probe_read_user(e->data, cl, (void *)buf))
        cl = 0;
    e->caplen = cl;
    __u32 size = offsetof(struct tls_data_event, data) + cl;
    if (size > sizeof(*e))
        size = sizeof(*e);
    if (!within_budget(e->hdr.run_cgroup_id, size))
        return 0;
    if (bpf_ringbuf_output(&events, e, size, 0))
        note_lost(e->hdr.run_cgroup_id);
    return 0;
}

/* At return: copy what the call wrote or read. Writes are taken at
 * return, with the count written, because a call made before the
 * handshake completes fails and is retried (6.0: Node). */
static __always_inline int tls_done(void *m, __u32 dir, __u32 lib, __s64 ret, int ex)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct tls_stash *st = bpf_map_lookup_elem(m, &id);
    if (!st)
        return 0;
    __u64 obj = st->obj, buf = st->buf, extra = st->extra;
    bpf_map_delete_elem(m, &id);
    __s64 n = ret;
    if (ex) {
        __u64 cnt = 0;
        if (ret != 1 || bpf_probe_read_user(&cnt, sizeof(cnt), (void *)extra))
            return 0;
        n = cnt;
    }
    return tls_emit(dir, lib, obj, buf, n);
}

/* The C libraries' probes (6.2, 6.4): one entry and one return program,
 * attached with uprobe-multi links per library and process. Each
 * attachment's cookie says what it is:
 *   bits 0-7   library: 1 libssl (OpenSSL or BoringSSL), 2 GnuTLS,
 *              4 OpenSSL linked into the binary
 *   bits 8-15  direction: 1 write, 2 read
 *   bit 16     an _ex form, whose count is stored through its 4th argument
 * SSL_write(ssl, buf, num), SSL_write_ex(ssl, buf, num, &written),
 * gnutls_record_send(session, buf, size) and their read forms all take
 * the connection and the buffer first. Multi links detach with one wait on
 * the kernel each; one link per probe made a process's exit cost about
 * 0.6 s of detaching, which held the next exec (6.4). */
#define TLS_COOKIE_LIB(c) ((__u32)((c) & 0xff))
#define TLS_COOKIE_DIR(c) ((__u32)(((c) >> 8) & 0xff))
#define TLS_COOKIE_EX(c)  ((int)(((c) >> 16) & 1))

SEC("uprobe.multi")
int tls_c_entry(struct pt_regs *ctx)
{
    __u64 c = bpf_get_attach_cookie(ctx);
    void *m = TLS_COOKIE_DIR(c) == 1 ? (void *)&tls_writes : (void *)&tls_reads;
    return tls_stash_call(m, (void *)PT_REGS_PARM1(ctx), (const void *)PT_REGS_PARM2(ctx),
                          TLS_COOKIE_EX(c) ? (void *)PT_REGS_PARM4(ctx) : 0);
}

SEC("uretprobe.multi")
int tls_c_return(struct pt_regs *ctx)
{
    __u64 c = bpf_get_attach_cookie(ctx);
    __u32 dir = TLS_COOKIE_DIR(c);
    void *m = dir == 1 ? (void *)&tls_writes : (void *)&tls_reads;
    __s64 ret = TLS_COOKIE_LIB(c) == 2 ? (__s64)PT_REGS_RC(ctx) : (__s64)(int)PT_REGS_RC(ctx);
    return tls_done(m, dir, TLS_COOKIE_LIB(c), ret, TLS_COOKIE_EX(c));
}

/* Go crypto/tls (milestone 6.3): (*Conn).Write and (*Conn).Read, linked
 * into each Go binary. Go's register ABI (ABIInternal) passes the
 * receiver, b.ptr and b.len in the first three integer registers and
 * returns n in the first; the goroutine (g) has a register of its own.
 * A uretprobe would rewrite the return address on a stack Go may move,
 * so the node agent puts the return probe on each of the function's
 * return instructions instead. A goroutine can change threads inside a
 * call, so calls are stashed by process and goroutine, not by thread.
 * Only the versions the node agent knows are probed. */
#if defined(__TARGET_ARCH_arm64)
#define GO_ARG0(c) (((struct user_pt_regs *)(c))->regs[0])
#define GO_ARG1(c) (((struct user_pt_regs *)(c))->regs[1])
#define GO_G(c)    (((struct user_pt_regs *)(c))->regs[28])
#elif defined(__TARGET_ARCH_x86)
#define GO_ARG0(c) ((c)->rax)
#define GO_ARG1(c) ((c)->rbx)
#define GO_G(c)    ((c)->r14)
#endif

#ifdef GO_G
struct tls_go_key {
    __u64 g;
    __u32 tgid;
    __u32 dir;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct tls_go_key);
    __type(value, struct tls_stash);
} tls_go_calls SEC(".maps");

static __always_inline int tls_go_enter(struct pt_regs *ctx, __u32 dir)
{
    struct tls_go_key k = {.g = GO_G(ctx), .tgid = bpf_get_current_pid_tgid() >> 32, .dir = dir};
    struct tls_stash st = {.obj = GO_ARG0(ctx), .buf = GO_ARG1(ctx)};
    bpf_map_update_elem(&tls_go_calls, &k, &st, BPF_ANY);
    return 0;
}

static __always_inline int tls_go_return(struct pt_regs *ctx, __u32 dir)
{
    struct tls_go_key k = {.g = GO_G(ctx), .tgid = bpf_get_current_pid_tgid() >> 32, .dir = dir};
    struct tls_stash *st = bpf_map_lookup_elem(&tls_go_calls, &k);
    if (!st)
        return 0;
    __u64 obj = st->obj, buf = st->buf;
    bpf_map_delete_elem(&tls_go_calls, &k);
    return tls_emit(dir, 3, obj, buf, (__s64)GO_ARG0(ctx));
}

/* Attached with uprobe-multi links: entries, and the return instructions
 * (as entry probes), the cookie giving the direction. */
SEC("uprobe.multi")
int tls_go_entry(struct pt_regs *ctx) { return tls_go_enter(ctx, TLS_COOKIE_DIR(bpf_get_attach_cookie(ctx))); }
SEC("uprobe.multi")
int tls_go_ret(struct pt_regs *ctx) { return tls_go_return(ctx, TLS_COOKIE_DIR(bpf_get_attach_cookie(ctx))); }
#endif

char LICENSE[] SEC("license") = "GPL";
