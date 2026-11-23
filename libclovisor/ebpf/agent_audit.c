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
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define MAX_PATH_LEN   256
#define MAX_ARGS_LEN   512  /* power of two: used as a mask */
#define MAX_CGPATH_LEN 128
#define MAX_DNS_LEN    1024 /* power of two: used as a mask */

#define ETH_P_IP     0x0800
#define ETH_P_IPV6   0x86DD
#define IPPROTO_UDP  17
#define IPPROTO_TCP_ 6
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

/* CO-RE: only the fields we need; relocated against kernel BTF at load. */
struct linux_binprm {
    const char *filename;
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
    __u32 _pad2;
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
    if (BPF_CORE_READ(cgrp, level) != cfg->agents_level + 1)
        return; /* the node agent checks the path is under agents/ */

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
    if (bpf_skb_load_bytes(skb, l4off + 8, e->payload, len & (MAX_DNS_LEN - 1) ?: MAX_DNS_LEN) < 0) {
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
        if (in_exceptions(cfg->udp_exc, ip, hport))
            return V_EXCEPTION;
        if (is_loopback(ip)) {
            if (hport == cfg->dns_port && cfg->dns_port != 0)
                return V_EXCEPTION;
            int who = loopback_listener(ctx, ip, port, run, 1);
            if (who == LISTENER_SAME)
                return V_SAME_RUN;
            if (who == LISTENER_NONE)
                return V_UNBOUND;
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

/* A reply from the resolver appears to come from the server the client
 * asked; resolvers drop replies from anyone else. */
SEC("cgroup/recvmsg4")
int on_recvmsg4(struct bpf_sock_addr *ctx)
{
    struct audit_config *cfg = get_config();
    if (!cfg || cfg->dns_port == 0)
        return 1;
    if (ctx->user_ip4 != bpf_htonl(0x7f000001) || ctx->user_port != bpf_htons(cfg->dns_port))
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
    if (!cfg || cfg->dns_port == 0 || ctx->user_port != bpf_htons(cfg->dns_port))
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
        return 0; /* the run's own socket */
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

char LICENSE[] SEC("license") = "GPL";
