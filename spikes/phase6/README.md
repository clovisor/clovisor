# Phase 6 milestone 6.0 spikes

Throwaway code that answered the 6.0 questions in
[the design doc](../../docs/agent-egress-design.md#60-spike-results-2026-11-24).
Separate Go modules (cilium/ebpf v0.22 needs Go 1.26; the Go client has no
dependencies, so Go 1.25 builds it too). Not production code. arm64 only:
the Go probes name arm64 registers.

| Path | What it shows |
|---|---|
| `bpf/tlscap.c` | Uprobes for tasks under one cgroup: OpenSSL `SSL_write`, `SSL_write_ex`, `SSL_read`, `SSL_read_ex`, and GnuTLS `gnutls_record_send`/`recv`, stashed at entry and copied at return; Go `crypto/tls.(*Conn).Write` and `Read` at entry and at each return instruction, stashed by goroutine (`x28`); syscall tracepoints that tie a TLS object to its socket; an exec tracepoint for per-process attachment, optionally stopping the process (`SIGSTOP`) until it is attached. |
| `tlscap/` | `server`: HTTPS (HTTP/1.1 and 2) on :8443 and a TLS sink on :8444. `probe`: loads and attaches, then decodes HTTP/1 request lines and HTTP/2 HEADERS (HPACK) from the captured bytes, skipping what a call wrote past the capture. `-capture=false` counts calls only; `-notp` drops the tracepoints; `-pid` attaches to one process; `-follow` attaches to each process as it execs in the cgroup, and `-hold` stops it until then. |
| `goclient/` | A Go HTTP/2 client, and a timed write loop to the sink (`-bench`). |

## Running

```sh
S=<dir with vmlinux.h>   # bpftool btf dump file /sys/kernel/btf/vmlinux format c > $S/vmlinux.h
clang -target bpf -D__TARGET_ARCH_arm64 -I$S -g -O2 -Wno-missing-declarations -c bpf/tlscap.c -o bpf/tlscap.o
go build -o /tmp/p6/ ./tlscap
(cd goclient && go build -o /tmp/p6/go126 . && GOTOOLCHAIN=go1.25.9 go build -o /tmp/p6/go125 .)
/tmp/p6/tlscap server &
sudo /tmp/p6/tlscap probe -go /tmp/p6/go125,/tmp/p6/go126 &   # creates /sys/fs/cgroup/spike6
sudo sh -c 'echo $$ > /sys/fs/cgroup/spike6/cgroup.procs; curl -sk https://localhost:8443/x; /tmp/p6/go126'
sudo pkill -INT -x tlscap   # prints the counts
```

The restart question was answered with a throwaway test in `integration/`
that ran the transparent environment, started two runs under `tp` (one
revoked), restarted the node agent, and compared what the runs could do.
