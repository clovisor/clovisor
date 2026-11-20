# Phase 2 milestone 2.0 spikes

Throwaway code that answered the 2.0 questions in
[the design doc](../../docs/agent-egress-design.md#20-spike-results-2026-11-20).
It is a separate Go module so its dependencies (go-control-plane, gRPC)
stay out of the main `go.mod`. Not production code.

| Path | What it shows |
|---|---|
| `sockdiag/` | Cgroup id of a TCP socket from its 4-tuple via `NETLINK_SOCK_DIAG` (`INET_DIAG_CGROUP_ID`). Unprivileged, about 3 µs. `go test -bench . ./sockdiag` |
| `extproc/` | Minimal `ext_proc` server: identity from the downstream address, host and path deny lists, narrated 403 (JSON body plus `x-clovisor-denial` header), body buffering. |
| `envoy/a-host.yaml` | Explicit forward proxy: CONNECT and plain HTTP, host-level decisions, dynamic forward proxy, nothing terminated. |
| `envoy/b-terminate.yaml` | As A, plus CONNECT to `example.com:443` ended and TLS terminated on an internal listener. The client address crosses the internal hop as transitive filter state and is written into `x-clovisor-client` by `header_mutation` before `ext_proc`, overwriting any client value. |

## Running

Needs the node agent running (for runs), Docker, and a CA plus an
`example.com` leaf certificate in `$PKI` (spike B only). The CA must carry
critical `basicConstraints` and `keyUsage`, or Python 3.13+ rejects it.

```sh
go build -o /tmp/extproc ./extproc
/tmp/extproc -listen 127.0.0.1:19001 -deny example.org -deny-path /admin &
sudo docker run --rm --network host -v $PWD/envoy:/cfg:ro -v $PKI:/pki:ro \
  --entrypoint envoy envoyproxy/envoy:v1.34-latest -c /cfg/b-terminate.yaml

# curl ignores upper-case HTTP_PROXY; set the lower-case variables.
https_proxy=http://127.0.0.1:18000 agentctl run -- \
  curl --cacert $PKI/ca.crt https://example.com/admin
```
