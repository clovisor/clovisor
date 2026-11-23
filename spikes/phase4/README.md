# Phase 4 milestone 4.0 spikes

Throwaway code that answered the 4.0 questions in
[the design doc](../../docs/agent-egress-design.md#40-spike-results-2026-11-23).
A separate Go module, on cilium/ebpf v0.22 (the main module is on v0.17,
which lacks the `cgroup/connect_unix` attach type). Not production code.

| Path | What it shows |
|---|---|
| `bpf/lsm.c` | BPF LSM hooks for a run cgroup: exec (`bpf_d_path`, owner and mode, read-only flags, the trusted-path walk across mounts, IMA hash), `socket_create` (raw and packet refused), `socket_connect` (Unix paths and abstract names; inet sockets created outside the run refused), `unix_stream_connect` and `unix_may_send` (the peer socket's cgroup), `socket_sendmsg` (foreign inet sockets refused). Also `cgroup/connect_unix`, and `lsm_cgroup` variants that only count calls. |
| `lsmspike/` | Loads each program on its own, so one the kernel or the library refuses does not hide the others; prints what the hooks see. `-enforce` refuses; `-no-ima` leaves out IMA hashing, to measure it. |

## Running

BPF LSM active (`bpf` in `/sys/kernel/security/lsm`), root, clang.

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
clang -target bpf -D__TARGET_ARCH_$(uname -m | sed s/aarch64/arm64/) -g -O2 \
  -Wno-missing-declarations -c bpf/lsm.c -o bpf/lsm.o
go build -o /tmp/p4/ ./...
sudo /tmp/p4/lsmspike -obj bpf/lsm.o [-enforce] &   # creates /sys/fs/cgroup/spike4
sudo mkdir /sys/fs/cgroup/spike4/run-a
inrun() { sudo sh -c 'echo $$ > /sys/fs/cgroup/spike4/run-a/cgroup.procs &&
  exec setpriv --reuid='"$(id -u)"' --regid='"$(id -g)"' --init-groups -- "$@"' sh "$@"; }
cp /bin/true /tmp/t && inrun /tmp/t      # untrusted path: EPERM with -enforce
inrun /bin/true                          # trusted

# lsm_cgroup, which cilium/ebpf cannot load: through libbpf.
sudo bpftool prog loadall bpf/lsm.o /sys/fs/bpf/spike4p
sudo bpftool cgroup attach /sys/fs/cgroup/spike4 lsm_cgroup pinned /sys/fs/bpf/spike4p/cg_socket_create
```

`bpf/vmlinux.h` is generated from the running kernel and not committed.
