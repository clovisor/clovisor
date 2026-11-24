// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

/*
 * Phase 6 spike: TLS plaintext from uprobes, for tasks under one cgroup.
 *
 *   libssl   SSL_write, SSL_write_ex at entry; SSL_read, SSL_read_ex at
 *            entry (stash) and return (copy what was read).
 *   Go       crypto/tls.(*Conn).Write at entry; (*Conn).Read at entry
 *            (stash by goroutine: the g pointer, x28 on arm64) and at each
 *            of its return instructions, since a uretprobe breaks Go's
 *            moving stacks.
 *   sockets  while a task is inside a TLS call, the fd of its next
 *            read/write syscall is the TLS object's socket.
 *
 * arm64 only (register names). Needs vmlinux.h for the running kernel.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define CAP 4096

enum { K_WRITE = 1, K_READ = 2, K_FD = 3, K_EXEC = 4 };
enum { L_SSL = 1, L_GO = 2, L_GNUTLS = 3 };

struct config {
    __u64 cg_id;
    __u32 cg_level;
    __u16 capture; /* 0: count calls only (cost of the trap alone) */
    __u16 hold;    /* follow mode: stop each exec until userspace attaches */
};

struct event {
    __u32 kind;
    __u32 lib;
    __u32 pid;
    __u32 tid;
    __u64 obj;   /* SSL * or *tls.Conn */
    __u32 len;   /* bytes the call wrote or read */
    __u32 caplen;
    __s32 fd;
    __u32 pad;
    __u8 data[CAP];
};

struct stash {
    __u64 obj;
    __u64 buf;
    __u64 extra; /* SSL_read_ex: size_t *readbytes */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct stash);
} reads SEC(".maps");

/* tid -> TLS object while inside a TLS call */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} inside SEC(".maps");

/* TLS object -> fd, once found */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __s32);
} objfd SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} calls SEC(".maps"); /* 0 writes, 1 reads, 2 ringbuf full */

static __always_inline struct config *ours(void)
{
    __u32 z = 0;
    struct config *c = bpf_map_lookup_elem(&cfg, &z);
    if (!c || !c->cg_id)
        return 0;
    if (bpf_get_current_ancestor_cgroup_id(c->cg_level) != c->cg_id)
        return 0;
    return c;
}

static __always_inline void count(__u32 k)
{
    __u64 *n = bpf_map_lookup_elem(&calls, &k);
    if (n)
        (*n)++;
}

static __always_inline void emit(struct config *c, __u32 kind, __u32 lib, __u64 obj, __u64 buf, __s64 n)
{
    count(kind == K_WRITE ? 0 : 1);
    if (!c->capture || n <= 0)
        return;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count(2);
        return;
    }
    __u64 id = bpf_get_current_pid_tgid();
    e->kind = kind;
    e->lib = lib;
    e->pid = id >> 32;
    e->tid = (__u32)id;
    e->obj = obj;
    e->len = n;
    __s32 *fd = bpf_map_lookup_elem(&objfd, &obj);
    e->fd = fd ? *fd : -1;
    __u32 cl = n > CAP ? CAP : (__u32)n;
    e->caplen = cl;
    if (bpf_probe_read_user(e->data, cl, (void *)buf))
        e->caplen = 0;
    bpf_ringbuf_submit(e, 0);
}

static __always_inline void enter(__u64 obj)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_update_elem(&inside, &tid, &obj, BPF_ANY);
}

static __always_inline void leave(void)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&inside, &tid);
}

/* ---- libssl and GnuTLS ----
 * Writes are copied at return, with what the call wrote: a call made
 * before the handshake completes fails and is retried, so entry would
 * record attempts, not data sent. Stashes are by thread. */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct stash);
} writes SEC(".maps");

static __always_inline int stash(void *m, void *obj, const void *buf, void *extra)
{
    if (!ours())
        return 0;
    __u64 id = bpf_get_current_pid_tgid();
    struct stash s = {.obj = (__u64)obj, .buf = (__u64)buf, .extra = (__u64)extra};
    bpf_map_update_elem(m, &id, &s, BPF_ANY);
    enter((__u64)obj);
    return 0;
}

/* ret: the call's return value, sign-correct for its type; ex: the _ex
 * form, which returns 1 and stores the count through extra. */
static __always_inline int done(void *m, __u32 kind, __u32 lib, __s64 ret, int ex)
{
    struct config *c = ours();
    if (!c)
        return 0;
    __u64 id = bpf_get_current_pid_tgid();
    struct stash *s = bpf_map_lookup_elem(m, &id);
    if (!s)
        return 0;
    __s64 n = ret;
    if (ex) {
        __u64 cnt = 0;
        if (ret != 1 || bpf_probe_read_user(&cnt, sizeof(cnt), (void *)s->extra))
            n = 0;
        else
            n = cnt;
    }
    emit(c, kind, lib, s->obj, s->buf, n);
    bpf_map_delete_elem(m, &id);
    leave();
    return 0;
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write, void *ssl, const void *buf, int num) { return stash(&writes, ssl, buf, 0); }
SEC("uprobe/SSL_write_ex")
int BPF_UPROBE(ssl_write_ex, void *ssl, const void *buf, size_t num, size_t *written) { return stash(&writes, ssl, buf, written); }
SEC("uretprobe/SSL_write")
int BPF_URETPROBE(ssl_write_ret, int ret) { return done(&writes, K_WRITE, L_SSL, ret, 0); }
SEC("uretprobe/SSL_write_ex")
int BPF_URETPROBE(ssl_write_ex_ret, int ret) { return done(&writes, K_WRITE, L_SSL, ret, 1); }

SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read, void *ssl, void *buf, int num) { return stash(&reads, ssl, buf, 0); }
SEC("uprobe/SSL_read_ex")
int BPF_UPROBE(ssl_read_ex, void *ssl, void *buf, size_t num, size_t *readbytes) { return stash(&reads, ssl, buf, readbytes); }
SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_read_ret, int ret) { return done(&reads, K_READ, L_SSL, ret, 0); }
SEC("uretprobe/SSL_read_ex")
int BPF_URETPROBE(ssl_read_ex_ret, int ret) { return done(&reads, K_READ, L_SSL, ret, 1); }

/* gnutls_record_send/recv(session, data, size) return ssize_t. */
SEC("uprobe/gnutls_send")
int BPF_UPROBE(gnutls_send, void *sess, const void *buf, size_t n) { return stash(&writes, sess, buf, 0); }
SEC("uretprobe/gnutls_send")
int BPF_URETPROBE(gnutls_send_ret, long ret) { return done(&writes, K_WRITE, L_GNUTLS, ret, 0); }
SEC("uprobe/gnutls_recv")
int BPF_UPROBE(gnutls_recv, void *sess, void *buf, size_t n) { return stash(&reads, sess, buf, 0); }
SEC("uretprobe/gnutls_recv")
int BPF_URETPROBE(gnutls_recv_ret, long ret) { return done(&reads, K_READ, L_GNUTLS, ret, 0); }

/* ---- Go crypto/tls (ABIInternal, arm64: receiver x0, b.ptr x1, b.len x2) ---- */

SEC("uprobe/go_write")
int go_write(struct pt_regs *ctx)
{
    struct config *c = ours();
    if (!c)
        return 0;
    __u64 conn = ctx->regs[0];
    enter(conn);
    emit(c, K_WRITE, L_GO, conn, ctx->regs[1], (__s64)ctx->regs[2]);
    return 0;
}

/* At Write's return instructions: only to leave. */
SEC("uprobe/go_write_ret")
int go_write_ret(struct pt_regs *ctx)
{
    if (ours())
        leave();
    return 0;
}

SEC("uprobe/go_read")
int go_read(struct pt_regs *ctx)
{
    if (!ours())
        return 0;
    __u64 g = ctx->regs[28];
    struct stash s = {.obj = ctx->regs[0], .buf = ctx->regs[1]};
    bpf_map_update_elem(&reads, &g, &s, BPF_ANY);
    enter(s.obj);
    return 0;
}

/* At Read's return instructions: n in x0. */
SEC("uprobe/go_read_ret")
int go_read_ret(struct pt_regs *ctx)
{
    struct config *c = ours();
    if (!c)
        return 0;
    __u64 g = ctx->regs[28];
    struct stash *s = bpf_map_lookup_elem(&reads, &g);
    if (!s)
        return 0;
    emit(c, K_READ, L_GO, s->obj, s->buf, (__s64)ctx->regs[0]);
    bpf_map_delete_elem(&reads, &g);
    leave();
    return 0;
}

/* ---- the socket under a TLS object ---- */

static __always_inline void sys_fd(long fd)
{
    if (!ours())
        return;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 *obj = bpf_map_lookup_elem(&inside, &tid);
    if (!obj)
        return;
    __s32 f = fd;
    __u64 o = *obj;
    if (bpf_map_update_elem(&objfd, &o, &f, BPF_NOEXIST) == 0) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e) - CAP, 0);
        if (!e)
            return;
        __u64 id = bpf_get_current_pid_tgid();
        e->kind = K_FD;
        e->lib = 0;
        e->pid = id >> 32;
        e->tid = (__u32)id;
        e->obj = o;
        e->fd = f;
        e->len = 0;
        e->caplen = 0;
        bpf_ringbuf_submit(e, 0);
    }
}

SEC("tracepoint/syscalls/sys_enter_write")
int tp_write(struct trace_event_raw_sys_enter *ctx) { sys_fd(ctx->args[0]); return 0; }
SEC("tracepoint/syscalls/sys_enter_read")
int tp_read(struct trace_event_raw_sys_enter *ctx) { sys_fd(ctx->args[0]); return 0; }
SEC("tracepoint/syscalls/sys_enter_sendto")
int tp_sendto(struct trace_event_raw_sys_enter *ctx) { sys_fd(ctx->args[0]); return 0; }
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tp_recvfrom(struct trace_event_raw_sys_enter *ctx) { sys_fd(ctx->args[0]); return 0; }
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tp_sendmsg(struct trace_event_raw_sys_enter *ctx) { sys_fd(ctx->args[0]); return 0; }
SEC("tracepoint/syscalls/sys_enter_recvmsg")
int tp_recvmsg(struct trace_event_raw_sys_enter *ctx) { sys_fd(ctx->args[0]); return 0; }

/* Follow mode: each exec in the cgroup, for per-process attachment. */
SEC("tracepoint/sched/sched_process_exec")
int tp_exec(void *ctx)
{
    if (!ours())
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e) - CAP, 0);
    if (!e)
        return 0;
    __u64 id = bpf_get_current_pid_tgid();
    e->kind = K_EXEC;
    e->lib = 0;
    e->pid = id >> 32;
    e->tid = (__u32)id;
    e->obj = bpf_ktime_get_ns();
    e->fd = -1;
    e->len = 0;
    e->caplen = 0;
    bpf_ringbuf_submit(e, 0);
    struct config *c = ours();
    if (c && c->hold)
        bpf_send_signal(19); /* SIGSTOP: userspace sends SIGCONT once attached */
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
