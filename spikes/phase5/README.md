# Phase 5 milestone 5.0 spikes

Throwaway code that answered the 5.0 questions in
[the design doc](../../docs/agent-egress-design.md#50-spike-results-2026-11-23).
A separate Go module (go-control-plane, quic-go, cilium/ebpf v0.22). Not
production code.

| Path | What it shows |
|---|---|
| `bodyspike/` | `extproc`: an `ext_proc` server whose behaviour each request picks with `x-spike`: buffered, streamed or partial request bodies, a streamed cap, a streamed body held in `ext_proc` and released redacted (`streamredact`), redaction and JSON injection (with the new `content-length`), SSE usage parsing (Anthropic and OpenAI shapes), and held requests (`hold:<s>` with `override_message_timeout`, `holdnoover:<s>` without). `upstream`: echoes bodies and streams SSE. `bench` and `hold`: load. |
| `envoy/body.yaml` | Envoy in front of the upstream with `ext_proc` set as the node agent sets it, plus `max_message_timeout` and a raised circuit breaker on the `ext_proc` cluster. |
| `quicsni/` | A UDP relay that decrypts QUIC v1 Initial packets (RFC 9001 §5), reassembles CRYPTO frames across datagrams, reads the ClientHello's server name, then forwards allowed names untouched to a quic-go server and drops the rest. `-bench` times one parse. |
| `bpf/hashcache.c`, `hashcache/` | A sleepable `bprm_check_security` hook that keeps a SHA-256 per (device, inode) in a BPF map, validated by `i_generation`, `i_version` and ctime, and hashes every exec fresh as well, to report whether the cache would have answered and whether its answer was stale. |

## Running

```sh
go build -o /tmp/p5/ ./bodyspike ./quicsni ./hashcache

# Bodies and held streams
/tmp/p5/bodyspike upstream & /tmp/p5/bodyspike extproc &
sudo docker run -d --name p5envoy --network host --ulimit nofile=65536:65536 \
  -v $PWD/envoy:/cfg:ro --entrypoint envoy envoyproxy/envoy:v1.34.14 -c /cfg/body.yaml
/tmp/p5/bodyspike bench -mode buf -size 1000000
curl -H 'x-spike: sse' -d '{}' http://127.0.0.1:18100/anthropic
ulimit -n 65536; /tmp/p5/bodyspike hold -n 4000 -secs 15

# QUIC
/tmp/p5/quicsni -run; /tmp/p5/quicsni -bench

# Exec hash cache: BPF LSM active, root, clang; vmlinux.h as in ../phase4.
clang -target bpf -D__TARGET_ARCH_$(uname -m | sed s/aarch64/arm64/) -I../phase4/bpf \
  -g -O2 -Wno-missing-declarations -c bpf/hashcache.c -o bpf/hashcache.o
sudo /tmp/p5/hashcache -obj bpf/hashcache.o &   # creates /sys/fs/cgroup/spike5
sudo mkdir /sys/fs/cgroup/spike5/run-a   # then exec things inside it, as in ../phase4
```
