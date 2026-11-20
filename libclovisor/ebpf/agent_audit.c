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
 *          subtree. Always returns 1 (allow) in Phase 1; this is the same
 *          hook Phase 2 turns into fail-closed enforcement.
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

#define AF_INET  2
#define AF_INET6 10

#define EVENT_EXEC    0
#define EVENT_CONNECT 1
#define EVENT_RUN_START 2
#define EVENT_RUN_END   3

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

/* Written once by the node agent: which cgroup is the agents root. */
struct audit_config {
    __u64 agents_cgroup_id;
    __u32 agents_level;   /* depth of agents dir below cgroup root */
    __u32 _pad;
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
};

/* hdr.cgroup_id and hdr.run_cgroup_id are both the run cgroup's id. */
struct cgroup_event {
    struct event_hdr hdr;
    char path[MAX_CGPATH_LEN]; /* relative to the cgroup root, e.g. /agents/run-x */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct audit_config);
} config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

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

    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

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

static __always_inline void emit_connect(struct bpf_sock_addr *ctx, __u16 family)
{
    struct event_hdr hdr = {};
    if (!fill_hdr(&hdr, EVENT_CONNECT))
        return;

    struct connect_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    e->hdr = hdr;
    e->family = family;
    e->dport = bpf_ntohs((__u16)ctx->user_port);
    e->protocol = ctx->protocol;
    __builtin_memset(e->daddr, 0, sizeof(e->daddr));

    if (family == AF_INET) {
        __u32 a = ctx->user_ip4;
        __builtin_memcpy(e->daddr, &a, 4);
    } else {
        __u32 a0 = ctx->user_ip6[0], a1 = ctx->user_ip6[1];
        __u32 a2 = ctx->user_ip6[2], a3 = ctx->user_ip6[3];
        __builtin_memcpy(&e->daddr[0], &a0, 4);
        __builtin_memcpy(&e->daddr[4], &a1, 4);
        __builtin_memcpy(&e->daddr[8], &a2, 4);
        __builtin_memcpy(&e->daddr[12], &a3, 4);
    }

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

    struct cgroup_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    __u64 id = BPF_CORE_READ(cgrp, kn, id);
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

SEC("cgroup/connect4")
int on_connect4(struct bpf_sock_addr *ctx)
{
    emit_connect(ctx, AF_INET);
    return 1; /* Phase 1: audit only, always allow */
}

SEC("cgroup/connect6")
int on_connect6(struct bpf_sock_addr *ctx)
{
    emit_connect(ctx, AF_INET6);
    return 1; /* Phase 1: audit only, always allow */
}

char LICENSE[] SEC("license") = "GPL";
