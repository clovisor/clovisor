// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

/*
 * Phase 4 spike: what BPF LSM can see and refuse for a run cgroup.
 * Not production code. Needs vmlinux.h from the running kernel:
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
 *
 * Global hooks (lsm/), filtered to tasks under the spike's agents cgroup:
 *   bprm_check_security  path (bpf_d_path), owner and mode, read-only
 *                        superblock or mount, and the trusted-path walk up
 *                        the directory chain across mounts. Enforce mode
 *                        refuses untrusted files.
 *   bprm_check_security  (sleepable) IMA hash of the file.
 *   socket_create        refuses raw IP and AF_PACKET.
 *   socket_connect       AF_UNIX path or abstract name; for inet sockets,
 *                        refuses a socket created outside the run.
 *   unix_stream_connect  the listening peer's cgroup.
 *   unix_may_send        the datagram peer's cgroup.
 *   socket_sendmsg       refuses sends on an inet socket created outside
 *                        the run.
 *
 * Per-cgroup hooks (lsm_cgroup/), attached to the agents cgroup, only
 * count calls: they show which hooks can be scoped by cgroup, and whose
 * cgroup (task or socket) the kernel uses.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1
#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10
#define AF_PACKET 17
#define SOCK_RAW 3
#define SB_RDONLY 1
#define MNT_READONLY 0x40
#define MAX_DEPTH 24

#define EV_EXEC 1
#define EV_IMA 2
#define EV_CREATE 3
#define EV_UNIX 4
#define EV_UNIX_PEER 5
#define EV_FOREIGN 6

/* Trust flags for exec events. */
#define T_ROOT_OWNED  1 /* file owned by root */
#define T_NOT_WRITABLE 2 /* file not writable by group or others */
#define T_PATH_TRUSTED 4 /* every ancestor directory root-owned, not group/other-writable */
#define T_RO_SB        8
#define T_RO_MNT       16
#define T_WALK_DONE    32 /* walk reached the global root within MAX_DEPTH */

struct config {
    __u64 agents_id;
    __u32 agents_level;
    __u32 enforce;
};

struct event {
    __u32 type;
    __s32 ret;   /* helper or decision result */
    __u64 run;
    __u64 other; /* peer or socket cgroup id */
    __u32 flags;
    __u32 depth;
    __u8 path[256];
    __u8 interp[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} spike_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

/* lsm_cgroup call counters, by hook. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} cg_calls SEC(".maps");

/* Scratch for the event being built: too big for the stack. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} scratch SEC(".maps");

static __always_inline struct config *cfg(void)
{
    __u32 zero = 0;
    struct config *c = bpf_map_lookup_elem(&spike_cfg, &zero);
    return c && c->agents_id ? c : 0;
}

static __always_inline __u64 current_run(struct config *c)
{
    if (bpf_get_current_ancestor_cgroup_id(c->agents_level) != c->agents_id)
        return 0;
    return bpf_get_current_ancestor_cgroup_id(c->agents_level + 1);
}

static __always_inline struct event *new_event(__u32 type, __u64 run)
{
    __u32 zero = 0;
    struct event *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));
    e->type = type;
    e->run = run;
    return e;
}

static __always_inline void submit(struct event *e)
{
    bpf_ringbuf_output(&events, e, sizeof(*e), 0);
}

/* The cgroup a socket was created in, and its ancestor at level (0 if the
 * socket's cgroup is shallower). */
static __always_inline __u64 sk_cgroup_at(struct sock *sk, __u32 level, __u64 *leaf)
{
    struct cgroup *cg = BPF_CORE_READ(sk, sk_cgrp_data.cgroup);
    if (!cg)
        return 0;
    *leaf = BPF_CORE_READ(cg, kn, id);
    int l = BPF_CORE_READ(cg, level);
    if (l < (int)level)
        return 0;
    struct cgroup *anc;
    if (bpf_core_read(&anc, sizeof(anc), &cg->ancestors[level & 31]) < 0 || !anc)
        return 0;
    return BPF_CORE_READ(anc, kn, id);
}

/* Is inode owned by root and not writable by group or others? */
static __always_inline int trusted_inode(struct inode *ino)
{
    if (!ino)
        return 0;
    __u32 uid = BPF_CORE_READ(ino, i_uid.val);
    __u16 mode = BPF_CORE_READ(ino, i_mode);
    return uid == 0 && !(mode & 0022);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(exec_check, struct linux_binprm *bprm, int ret)
{
    if (ret)
        return ret < 0 && ret >= -4095 ? ret : -EPERM;
    struct config *c = cfg();
    if (!c)
        return 0;
    __u64 run = current_run(c);
    if (!run)
        return 0;
    struct event *e = new_event(EV_EXEC, run);
    if (!e)
        return 0;

    /* Direct access keeps the pointer trusted, as bpf_d_path requires. */
    struct file *f = bprm->file;
    e->ret = bpf_d_path(&f->f_path, (char *)e->path, sizeof(e->path));
    const char *interp = BPF_CORE_READ(bprm, interp);
    bpf_probe_read_kernel_str(e->interp, sizeof(e->interp), interp);

    struct inode *ino = BPF_CORE_READ(f, f_inode);
    if (BPF_CORE_READ(ino, i_uid.val) == 0)
        e->flags |= T_ROOT_OWNED;
    if (!(BPF_CORE_READ(ino, i_mode) & 0022))
        e->flags |= T_NOT_WRITABLE;
    struct vfsmount *mnt = BPF_CORE_READ(f, f_path.mnt);
    if (BPF_CORE_READ(mnt, mnt_sb, s_flags) & SB_RDONLY)
        e->flags |= T_RO_SB;
    if (BPF_CORE_READ(mnt, mnt_flags) & MNT_READONLY)
        e->flags |= T_RO_MNT;

    /* Walk up from the file's directory, crossing mount points. */
    struct dentry *d = BPF_CORE_READ(f, f_path.dentry, d_parent);
    struct mount *m = container_of(mnt, struct mount, mnt);
    int trusted = 1;
    __u32 depth = 0;
    for (int i = 0; i < MAX_DEPTH; i++) {
        struct dentry *mroot = BPF_CORE_READ(m, mnt.mnt_root);
        if (d == mroot) {
            struct mount *parent = BPF_CORE_READ(m, mnt_parent);
            if (parent == m) {
                /* The global root: check it, and stop. */
                if (!trusted_inode(BPF_CORE_READ(d, d_inode)))
                    trusted = 0;
                e->flags |= T_WALK_DONE;
                break;
            }
            d = BPF_CORE_READ(m, mnt_mountpoint);
            m = parent;
            continue; /* the mountpoint is checked on the next round */
        }
        if (!trusted_inode(BPF_CORE_READ(d, d_inode)))
            trusted = 0;
        d = BPF_CORE_READ(d, d_parent);
        depth++;
    }
    e->depth = depth;
    if (trusted && (e->flags & T_WALK_DONE))
        e->flags |= T_PATH_TRUSTED;

    int file_ok = (e->flags & (T_ROOT_OWNED | T_NOT_WRITABLE)) == (T_ROOT_OWNED | T_NOT_WRITABLE);
    int deny = c->enforce && !(file_ok && (e->flags & T_PATH_TRUSTED));
    submit(e);
    return deny ? -EPERM : 0;
}

SEC("lsm.s/bprm_check_security")
int BPF_PROG(exec_ima, struct linux_binprm *bprm, int ret)
{
    if (ret)
        return ret < 0 && ret >= -4095 ? ret : -EPERM;
    struct config *c = cfg();
    if (!c)
        return 0;
    __u64 run = current_run(c);
    if (!run)
        return 0;
    struct event *e = new_event(EV_IMA, run);
    if (!e)
        return 0;
    struct file *f = bprm->file;
    e->ret = bpf_ima_file_hash(f, e->path, 32); /* hash algorithm id, or -errno */
    submit(e);
    return 0;
}

SEC("lsm/socket_create")
int BPF_PROG(sock_create, int family, int type, int protocol, int kern, int ret)
{
    if (ret)
        return ret < 0 && ret >= -4095 ? ret : -EPERM;
    if (kern)
        return 0;
    struct config *c = cfg();
    if (!c)
        return 0;
    __u64 run = current_run(c);
    if (!run)
        return 0;
    int raw = family == AF_PACKET || ((family == AF_INET || family == AF_INET6) && type == SOCK_RAW);
    if (!raw)
        return 0;
    int decision = c->enforce ? -EPERM : 0;
    struct event *e = new_event(EV_CREATE, run);
    if (!e)
        return decision;
    e->other = family;
    e->flags = type;
    e->ret = decision;
    submit(e);
    return decision;
}

/* For an inet socket in a run's task: refuse it if it was created outside
 * the run (inherited, or passed in). */
static __always_inline int foreign(struct socket *sock, struct config *c, __u64 run, int is_send)
{
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;
    __u16 fam = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (fam != AF_INET && fam != AF_INET6)
        return 0;
    __u64 leaf = 0;
    __u64 sk_run = sk_cgroup_at(sk, c->agents_level + 1, &leaf);
    if (sk_run == run)
        return 0;
    int decision = c->enforce ? -EPERM : 0;
    struct event *e = new_event(EV_FOREIGN, run);
    if (!e)
        return decision;
    e->other = leaf;
    e->flags = is_send;
    e->ret = decision;
    submit(e);
    return decision;
}

SEC("lsm/socket_connect")
int BPF_PROG(sock_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    if (ret)
        return ret < 0 && ret >= -4095 ? ret : -EPERM;
    struct config *c = cfg();
    if (!c)
        return 0;
    __u64 run = current_run(c);
    if (!run)
        return 0;
    __u16 fam = BPF_CORE_READ(address, sa_family);
    if (fam != AF_UNIX)
        return foreign(sock, c, run, 0);
    struct event *e = new_event(EV_UNIX, run);
    if (!e)
        return 0;
    struct sockaddr_un *un = (struct sockaddr_un *)address;
    /* An abstract name starts with a NUL; keep it, and say so. */
    bpf_probe_read_kernel(e->path, sizeof(un->sun_path), un->sun_path);
    e->flags = e->path[0] == 0; /* abstract */
    e->depth = addrlen;
    submit(e);
    return 0;
}

SEC("lsm/unix_stream_connect")
int BPF_PROG(unix_peer, struct sock *sock, struct sock *other, struct sock *newsk, int ret)
{
    if (ret)
        return ret < 0 && ret >= -4095 ? ret : -EPERM;
    struct config *c = cfg();
    if (!c)
        return 0;
    __u64 run = current_run(c);
    if (!run)
        return 0;
    struct event *e = new_event(EV_UNIX_PEER, run);
    if (!e)
        return 0;
    __u64 leaf = 0;
    __u64 peer_run = sk_cgroup_at(other, c->agents_level + 1, &leaf);
    e->other = leaf;
    e->flags = peer_run == run; /* same run */
    submit(e);
    return 0;
}

SEC("lsm/unix_may_send")
int BPF_PROG(unix_send, struct socket *sock, struct socket *other, int ret)
{
    if (ret)
        return ret < 0 && ret >= -4095 ? ret : -EPERM;
    struct config *c = cfg();
    if (!c)
        return 0;
    __u64 run = current_run(c);
    if (!run)
        return 0;
    struct event *e = new_event(EV_UNIX_PEER, run);
    if (!e)
        return 0;
    __u64 leaf = 0;
    __u64 peer_run = sk_cgroup_at(BPF_CORE_READ(other, sk), c->agents_level + 1, &leaf);
    e->other = leaf;
    e->flags = (peer_run == run) | 2; /* 2: datagram */
    submit(e);
    return 0;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(sock_sendmsg, struct socket *sock, struct msghdr *msg, int size, int ret)
{
    if (ret)
        return ret < 0 && ret >= -4095 ? ret : -EPERM;
    struct config *c = cfg();
    if (!c)
        return 0;
    __u64 run = current_run(c);
    if (!run)
        return 0;
    return foreign(sock, c, run, 1);
}

/* cgroup/connect_unix (6.7): the socket-address hook for Unix sockets,
 * scoped to the agents cgroup like connect4, no BPF LSM needed. */
extern void *bpf_cast_to_kern_ctx(void *) __ksym;

SEC("cgroup/connect_unix")
int unix_connect_hook(struct bpf_sock_addr *ctx)
{
    struct config *c = cfg();
    if (!c)
        return 1;
    __u64 run = current_run(c);
    if (!run)
        return 1;
    struct bpf_sock_addr_kern *k = bpf_cast_to_kern_ctx(ctx);
    struct event *e = new_event(EV_UNIX, run);
    if (!e)
        return 1;
    struct sockaddr_un *un = (struct sockaddr_un *)k->uaddr;
    bpf_probe_read_kernel(e->path, sizeof(un->sun_path), un->sun_path);
    e->flags = (e->path[0] == 0) | 4; /* 4: from connect_unix */
    e->depth = k->uaddrlen;
    submit(e);
    return 1;
}

/* Per-cgroup variants: count calls only. */
static __always_inline void count(__u32 k)
{
    __u64 *n = bpf_map_lookup_elem(&cg_calls, &k);
    if (n)
        __sync_fetch_and_add(n, 1);
}

SEC("lsm_cgroup/socket_create")
int BPF_PROG(cg_socket_create, int family, int type, int protocol, int kern)
{
    count(0);
    return 1;
}

SEC("lsm_cgroup/socket_connect")
int BPF_PROG(cg_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    count(1);
    return 1;
}

SEC("lsm_cgroup/socket_sendmsg")
int BPF_PROG(cg_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
    count(2);
    return 1;
}

SEC("lsm_cgroup/unix_stream_connect")
int BPF_PROG(cg_unix_stream_connect, struct sock *sock, struct sock *other, struct sock *newsk)
{
    count(3);
    return 1;
}

SEC("lsm_cgroup/bprm_check_security")
int BPF_PROG(cg_bprm_check, struct linux_binprm *bprm)
{
    count(4);
    return 1;
}

char LICENSE[] SEC("license") = "GPL";
