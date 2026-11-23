// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

/*
 * Phase 5 spike: can an exec hash cache in a BPF map be trusted?
 *
 * Keyed by (device, inode), validated by i_generation, i_version and ctime.
 * Every exec under the spike cgroup is also hashed fresh with
 * bpf_ima_file_hash, so the event says whether the cache would have
 * answered, and whether that answer would have been stale.
 * Needs vmlinux.h from the running kernel (see ../README.md).
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct config {
    __u64 agents_id;
    __u32 agents_level;
    __u32 pad;
};

struct hkey {
    __u64 dev;
    __u64 ino;
};

struct hval {
    __u64 version;
    __s64 ctime_sec;
    __u32 ctime_nsec;
    __u32 gen;
    __u8 hash[32];
};

struct event {
    __u64 ino;
    __u64 version;
    __s64 ctime_sec;
    __u32 ctime_nsec;
    __u32 gen;
    __u32 lookup_ns; /* cache lookup and compare */
    __u32 hash_ns;   /* bpf_ima_file_hash */
    __s32 ret;
    __u8 hit;   /* key and validators matched */
    __u8 stale; /* matched, but the cached hash differs from the fresh one */
    __u8 sb_iversion; /* SB_I_VERSION on the superblock */
    __u8 pad;
    __u32 s_magic;
    __u8 hash[8];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} spike_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct hkey);
    __type(value, struct hval);
} hash_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct hval);
} scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("lsm.s/bprm_check_security")
int BPF_PROG(exec_hash, struct linux_binprm *bprm, int ret)
{
    if (ret)
        return ret < 0 && ret >= -4095 ? ret : -1;
    __u32 zero = 0;
    struct config *c = bpf_map_lookup_elem(&spike_cfg, &zero);
    if (!c || !c->agents_id || bpf_get_current_ancestor_cgroup_id(c->agents_level) != c->agents_id)
        return 0;
    struct file *f = bprm->file;
    struct inode *in = BPF_CORE_READ(f, f_inode);
    struct hkey k = {};
    k.dev = BPF_CORE_READ(in, i_sb, s_dev);
    k.ino = BPF_CORE_READ(in, i_ino);
    struct hval *cur = bpf_map_lookup_elem(&scratch, &zero);
    if (!cur)
        return 0;
    cur->version = BPF_CORE_READ(in, i_version.counter);
    cur->ctime_sec = BPF_CORE_READ(in, i_ctime_sec);
    cur->ctime_nsec = BPF_CORE_READ(in, i_ctime_nsec);
    cur->gen = BPF_CORE_READ(in, i_generation);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));
    e->ino = k.ino;
    e->version = cur->version;
    e->ctime_sec = cur->ctime_sec;
    e->ctime_nsec = cur->ctime_nsec;
    e->gen = cur->gen;
    e->sb_iversion = !!(BPF_CORE_READ(in, i_sb, s_flags) & (1UL << 23));
    e->s_magic = BPF_CORE_READ(in, i_sb, s_magic);

    __u64 t0 = bpf_ktime_get_ns();
    struct hval *v = bpf_map_lookup_elem(&hash_cache, &k);
    int hit = v && v->version == cur->version && v->ctime_sec == cur->ctime_sec &&
              v->ctime_nsec == cur->ctime_nsec && v->gen == cur->gen;
    __u64 t1 = bpf_ktime_get_ns();
    e->ret = bpf_ima_file_hash(f, cur->hash, 32);
    __u64 t2 = bpf_ktime_get_ns();
    e->lookup_ns = t1 - t0;
    e->hash_ns = t2 - t1;
    e->hit = hit;
    if (hit) {
        for (int i = 0; i < 32; i++)
            if (v->hash[i] != cur->hash[i]) {
                e->stale = 1;
                break;
            }
    }
    for (int i = 0; i < 8; i++)
        e->hash[i] = cur->hash[i];
    if (e->ret >= 0)
        bpf_map_update_elem(&hash_cache, &k, cur, BPF_ANY);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
