// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

/*
 * Phase 3 spike: transparent redirect-or-deny for run cgroups.
 * Not production code.
 *
 * Attached to /sys/fs/cgroup/agents (every run):
 *   cgroup/connect4,6     TCP: same-run loopback and the exceptions go direct;
 *                         everything else is redirected to the transparent
 *                         listener, or refused (EPERM) if the heartbeat is
 *                         stale. UDP: port 53 goes to the local resolver,
 *                         anything else is refused.
 *   cgroup/sendmsg4,6     unconnected UDP, same rule as UDP connect.
 *   cgroup/recvmsg4,6     replies from the local resolver appear to come from
 *                         the resolver the client asked.
 *   cgroup/getpeername4,6 a redirected socket reports its original peer.
 *   cgroup/bind4,6        tags the socket with its run, so a later loopback
 *                         connect can tell whether the listener is in the
 *                         same run.
 *   sockops               on the client's ESTABLISHED callback, re-keys the
 *                         original destination by the client's address and
 *                         port, which the proxy sees as its peer.
 *
 * Attached to the proxy's cgroup:
 *   cgroup/getsockopt     answers SO_ORIGINAL_DST (SOL_IP and SOL_IPV6) from
 *                         that map.
 *
 * Addresses are kept as 16 bytes, IPv4 as IPv4-mapped (::ffff:a.b.c.d), so
 * a dual-stack client socket and the proxy's IPv4 socket agree on a key.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET  2
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM  2
#define SOL_IP   0
#define SOL_IPV6 41
#define SO_ORIGINAL_DST 80 /* also IP6T_SO_ORIGINAL_DST */

#define MODE_AUDIT   1
#define MODE_ENFORCE 2

#define V_REDIRECT       1
#define V_DENY_UNHEALTHY 2
#define V_DENY_UDP       3
#define V_SAME_RUN       4
#define V_EXCEPTION      5
#define V_DNS            6
#define V_AUDIT_REDIRECT 7
#define V_AUDIT_DENY     8

struct config {
    __u64 agents_cgroup_id;
    __u32 agents_level;
    __u32 mode;
    __u64 heartbeat_ns;   /* CLOCK_MONOTONIC, written by the node agent */
    __u64 stale_ns;       /* older than this: unhealthy */
    __u16 proxy_port;     /* transparent listener, host order */
    __u16 dns_port;       /* local resolver, host order */
    __u16 explicit_port;  /* explicit proxy: exception, host order */
    __u16 _pad;
};

struct addr {
    __u32 a[4];           /* network order; IPv4 as ::ffff:a.b.c.d */
};

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

struct verdict {
    __u64 run;
    __u32 verdict;
    __u16 port;           /* network order */
    __u16 type;
    struct addr ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config SEC(".maps");

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

/* The proxy's view: its peer (the client) to the original destination. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct tuple_key);
    __type(value, struct orig);
} orig_by_tuple SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} verdicts SEC(".maps");

/*
 * A direct 32-bit load of a ctx or sock field. Plain C lets the compiler fold
 * two loads of neighbouring fields behind a branch into one load at a
 * computed offset, which the verifier refuses for sock and ctx pointers.
 */
#define LOAD32(ptr, type, field) ({                                          \
    __u32 __v;                                                            \
    asm volatile("%0 = *(u32 *)(%1 + %2)"                                 \
                 : "=r"(__v) : "r"(ptr), "i"(__builtin_offsetof(type, field))); \
    __v; })

static __always_inline struct config *cfg(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&config, &zero);
}

/* Run cgroup id of the current task, 0 if it is not in a run. */
static __always_inline __u64 current_run(struct config *c)
{
    if (c->agents_cgroup_id == 0)
        return 0;
    if (bpf_get_current_ancestor_cgroup_id(c->agents_level) != c->agents_cgroup_id)
        return 0;
    return bpf_get_current_ancestor_cgroup_id(c->agents_level + 1);
}

static __always_inline int healthy(struct config *c)
{
    __u64 hb = c->heartbeat_ns;
    return hb != 0 && bpf_ktime_get_ns() - hb < c->stale_ns;
}

static __always_inline void emit(__u64 run, __u32 v, __u16 type, struct addr *ip, __u16 port)
{
    struct verdict *e = bpf_ringbuf_reserve(&verdicts, sizeof(*e), 0);
    if (!e)
        return;
    e->run = run;
    e->verdict = v;
    e->type = type;
    e->port = port;
    e->ip = *ip;
    bpf_ringbuf_submit(e, 0);
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

#define LISTENER_NONE  0
#define LISTENER_SAME  1
#define LISTENER_OTHER 2

/*
 * Who listens at ip:port: nobody, this run (the socket was bound by it), or
 * someone else. With nobody listening the connect is left alone: it fails
 * with ECONNREFUSED, as it would without Clovisor, and a client trying ::1
 * before 127.0.0.1 falls back. Redirecting it would make the proxy answer.
 */
static __always_inline int loopback_listener(struct bpf_sock_addr *ctx, struct addr *ip, __u16 port, __u64 run)
{
    struct bpf_sock_tuple t = {};
    struct bpf_sock *sk;

    if (is_v4mapped(ip)) {
        t.ipv4.daddr = ip->a[3];
        t.ipv4.dport = port;
        sk = bpf_sk_lookup_tcp(ctx, &t, sizeof(t.ipv4), BPF_F_CURRENT_NETNS, 0);
    } else {
        __builtin_memcpy(t.ipv6.daddr, ip->a, 16);
        t.ipv6.dport = port;
        sk = bpf_sk_lookup_tcp(ctx, &t, sizeof(t.ipv6), BPF_F_CURRENT_NETNS, 0);
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
 * The shared decision. ip and port are the destination the client asked for.
 * Returns 1 to let the (possibly rewritten) call proceed, 0 for EPERM.
 * On redirect, *to_port is the port to rewrite to and *rewrite is set.
 */
static __always_inline int decide(struct bpf_sock_addr *ctx, struct addr *ip, __u16 port, __u16 *to_port, int *rewrite)
{
    struct config *c = cfg();
    if (!c)
        return 1;
    __u64 run = current_run(c);
    if (run == 0)
        return 1;
    *rewrite = 0;
    __u16 hport = bpf_ntohs(port);
    __u16 type = ctx->type;

    if (type == SOCK_STREAM) {
        if (is_loopback(ip)) {
            if (hport == c->explicit_port || hport == c->proxy_port || hport == c->dns_port) {
                emit(run, V_EXCEPTION, type, ip, port);
                return 1;
            }
            int who = loopback_listener(ctx, ip, port, run);
            if (who == LISTENER_SAME) {
                emit(run, V_SAME_RUN, type, ip, port);
                return 1;
            }
            if (who == LISTENER_NONE)
                return 1;
        }
        if (c->mode != MODE_ENFORCE) {
            emit(run, healthy(c) ? V_AUDIT_REDIRECT : V_AUDIT_DENY, type, ip, port);
            return 1;
        }
        if (!healthy(c)) {
            emit(run, V_DENY_UNHEALTHY, type, ip, port);
            return 0;
        }
        emit(run, hport == 53 ? V_DNS : V_REDIRECT, type, ip, port);
        *to_port = hport == 53 ? c->dns_port : c->proxy_port;
        *rewrite = 1;
        return 1;
    }

    if (type == SOCK_DGRAM) {
        if (hport == 53) {
            if (c->mode != MODE_ENFORCE)
                return 1;
            if (!healthy(c)) {
                emit(run, V_DENY_UNHEALTHY, type, ip, port);
                return 0;
            }
            /* Not emitted: one event per datagram would flood. */
            *to_port = c->dns_port;
            *rewrite = 1;
            return 1;
        }
        if (is_loopback(ip) && hport == c->dns_port)
            return 1;
        emit(run, c->mode == MODE_ENFORCE ? V_DENY_UDP : V_AUDIT_DENY, type, ip, port);
        return c->mode != MODE_ENFORCE;
    }
    return 1;
}

static __always_inline void stash(struct bpf_sock_addr *ctx, struct addr *ip, __u16 port, __u16 family)
{
    struct orig *o = bpf_sk_storage_get(&orig_by_sk, ctx->sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (!o)
        return;
    o->ip = *ip;
    o->port = port;
    o->family = family;
}

static __always_inline int addr4(struct bpf_sock_addr *ctx)
{
    struct addr ip;
    __u16 to_port = 0;
    int rewrite = 0;
    v4mapped(&ip, ctx->user_ip4);
    __u16 port = (__u16)ctx->user_port;
    if (!decide(ctx, &ip, port, &to_port, &rewrite))
        return 0;
    if (rewrite) {
        stash(ctx, &ip, port, AF_INET);
        ctx->user_ip4 = bpf_htonl(0x7f000001);
        ctx->user_port = bpf_htons(to_port);
    }
    return 1;
}

static __always_inline int addr6(struct bpf_sock_addr *ctx)
{
    struct addr ip;
    __u16 to_port = 0;
    int rewrite = 0;
    ip.a[0] = ctx->user_ip6[0];
    ip.a[1] = ctx->user_ip6[1];
    ip.a[2] = ctx->user_ip6[2];
    ip.a[3] = ctx->user_ip6[3];
    __u16 port = (__u16)ctx->user_port;
    if (!decide(ctx, &ip, port, &to_port, &rewrite))
        return 0;
    if (rewrite) {
        int mapped = is_v4mapped(&ip);
        stash(ctx, &ip, port, mapped ? AF_INET : AF_INET6);
        if (mapped) {
            /* Dual-stack socket to an IPv4 address: keep it IPv4. */
            ctx->user_ip6[3] = bpf_htonl(0x7f000001);
        } else {
            ctx->user_ip6[0] = 0;
            ctx->user_ip6[1] = 0;
            ctx->user_ip6[2] = 0;
            ctx->user_ip6[3] = bpf_htonl(1);
        }
        ctx->user_port = bpf_htons(to_port);
    }
    return 1;
}

SEC("cgroup/connect4")
int t_connect4(struct bpf_sock_addr *ctx) { return addr4(ctx); }

SEC("cgroup/connect6")
int t_connect6(struct bpf_sock_addr *ctx) { return addr6(ctx); }

SEC("cgroup/sendmsg4")
int t_sendmsg4(struct bpf_sock_addr *ctx) { return addr4(ctx); }

SEC("cgroup/sendmsg6")
int t_sendmsg6(struct bpf_sock_addr *ctx) { return addr6(ctx); }

/* Rewrite the source of a reply, or the peer, back to the original. */
static __always_inline void restore4(struct bpf_sock_addr *ctx, int dgram_only)
{
    if (dgram_only && ctx->type != SOCK_DGRAM)
        return;
    struct orig *o = bpf_sk_storage_get(&orig_by_sk, ctx->sk, 0, 0);
    if (!o || o->family != AF_INET)
        return;
    if (ctx->user_ip4 != bpf_htonl(0x7f000001))
        return;
    ctx->user_ip4 = o->ip.a[3];
    ctx->user_port = o->port;
}

static __always_inline void restore6(struct bpf_sock_addr *ctx, int dgram_only)
{
    if (dgram_only && ctx->type != SOCK_DGRAM)
        return;
    struct orig *o = bpf_sk_storage_get(&orig_by_sk, ctx->sk, 0, 0);
    if (!o)
        return;
    ctx->user_ip6[0] = o->ip.a[0];
    ctx->user_ip6[1] = o->ip.a[1];
    ctx->user_ip6[2] = o->ip.a[2];
    ctx->user_ip6[3] = o->ip.a[3];
    ctx->user_port = o->port;
}

SEC("cgroup/recvmsg4")
int t_recvmsg4(struct bpf_sock_addr *ctx) { restore4(ctx, 1); return 1; }

SEC("cgroup/recvmsg6")
int t_recvmsg6(struct bpf_sock_addr *ctx) { restore6(ctx, 1); return 1; }

SEC("cgroup/getpeername4")
int t_getpeername4(struct bpf_sock_addr *ctx) { restore4(ctx, 0); return 1; }

SEC("cgroup/getpeername6")
int t_getpeername6(struct bpf_sock_addr *ctx) { restore6(ctx, 0); return 1; }

static __always_inline int tag(struct bpf_sock_addr *ctx)
{
    struct config *c = cfg();
    if (!c)
        return 1;
    __u64 run = current_run(c);
    if (run == 0)
        return 1;
    __u64 *v = bpf_sk_storage_get(&run_by_sk, ctx->sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (v)
        *v = run;
    return 1;
}

SEC("cgroup/bind4")
int t_bind4(struct bpf_sock_addr *ctx) { return tag(ctx); }

SEC("cgroup/bind6")
int t_bind6(struct bpf_sock_addr *ctx) { return tag(ctx); }

SEC("sockops")
int t_sockops(struct bpf_sock_ops *skops)
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
    struct tuple_key k = {};
    if (family == AF_INET) {
        v4mapped(&k.ip, l4);
    } else {
        k.ip.a[0] = l0;
        k.ip.a[1] = l1;
        k.ip.a[2] = l2;
        k.ip.a[3] = l3;
    }
    k.port = bpf_htons((__u16)skops->local_port); /* local_port is host order */
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

SEC("cgroup/getsockopt")
int t_getsockopt(struct bpf_sockopt *ctx)
{
    if (ctx->optname != SO_ORIGINAL_DST || (ctx->level != SOL_IP && ctx->level != SOL_IPV6))
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
    struct tuple_key k = {};
    if (family == AF_INET) {
        v4mapped(&k.ip, d4);
    } else {
        k.ip.a[0] = d0;
        k.ip.a[1] = d1;
        k.ip.a[2] = d2;
        k.ip.a[3] = d3;
    }
    k.port = (__u16)sk->dst_port; /* network order in the low 16 bits */
    struct orig *o = bpf_map_lookup_elem(&orig_by_tuple, &k);
    if (!o)
        return 1;

    void *start = ctx->optval, *end = ctx->optval_end;
    if (ctx->level == SOL_IP) {
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

char LICENSE[] SEC("license") = "GPL";
