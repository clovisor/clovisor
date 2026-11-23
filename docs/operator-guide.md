# Clovisor operator guide

Clovisor governs what AI agent processes may reach on the network, and which
MCP tools they may call. Each agent invocation is a **run**. A run gets a
profile, and every egress decision is recorded in a per-run timeline. This
guide covers deploying and operating it. The design and its reasoning are in
[agent-egress-design.md](agent-egress-design.md).

- [1. What you are deploying](#1-what-you-are-deploying)
- [2. Choosing an identity mode](#2-choosing-an-identity-mode)
- [3. Build](#3-build)
- [4. Run the node agent](#4-run-the-node-agent)
- [5. Run Envoy](#5-run-envoy)
- [6. Policy](#6-policy)
- [7. Running agents](#7-running-agents)
- [8. From observation to enforcement](#8-from-observation-to-enforcement)
- [9. MCP](#9-mcp)
- [10. TLS termination](#10-tls-termination)
- [11. Transparent mode (Linux)](#11-transparent-mode-linux)
- [12. Incident response](#12-incident-response)
- [13. Audit data](#13-audit-data)
- [14. Security notes and limits](#14-security-notes-and-limits)
- [15. Troubleshooting](#15-troubleshooting)
- [16. Testing a deployment](#16-testing-a-deployment)

## 1. What you are deploying

| Component | What it does | Runs as |
|---|---|---|
| `node-agent` | The run API (`agentctl` talks to it), the policy engine, `ext_proc` for Envoy, the local MCP gateway, the node CA, the timeline recorder. With cgroup identity, it also loads the BPF audit program. | root (cgroup identity), or any user (credential identity) |
| Envoy | The explicit proxy runs use, with `HTTP(S)_PROXY` pointing at it. It asks `ext_proc` about every CONNECT and request. The node agent writes its bootstrap. | uid 101 in the official image, or the node agent's user |
| `agentctl` | Starts runs, and reads timelines, learns, checks and reviews. | any user, no privileges |

One node agent and one Envoy serve every run on a machine.

## 2. Choosing an identity mode

The proxy must know which run each connection belongs to.

| | `cgroup` (default on Linux) | `credential` (default elsewhere) |
|---|---|---|
| How a run is known | The cgroup of the client socket (socket diagnostics). A child of the run cannot leave it. | A per-run secret in the proxy URL (`http://run-<id>:<token>@…`). |
| Strength | Enforcement-grade for anything that uses the proxy. | A claim: any process holding the secret speaks for the run. |
| Kernel audit (exec, connect, DNS) | Yes (BPF) | No: timelines hold proxy and MCP events only. |
| A run started inside a run | Nested: bounded by its parent's policy, clamps cascade. | Not bounded: a run may start another run within its user's ceiling, escaping its own clamps. |
| Needs | Linux 5.7+, cgroup v2, root, the BPF object | Nothing: macOS, containers, an unprivileged user. |

In both modes the proxy is **explicit**. A process that ignores
`HTTPS_PROXY`, such as `curl --noproxy '*'`, goes around it. Pair Clovisor
with something that forbids other egress (a network namespace, an OS sandbox
profile, a firewall rule) when bypass matters. Phase 3 adds a transparent
redirect on Linux. The enforcement receipt (`agentctl explain`) states which
identity applies.

## 3. Build

```sh
make build            # BPF object, agentctl, node-agent (Linux, needs clang)
make agentctl node-agent
make check            # vet, build, unit tests, and the macOS cross-build
```

On macOS, or anywhere without clang, build only the Go binaries:

```sh
go build -o bin/agentctl ./cmd/agentctl
go build -o bin/node-agent ./cmd/node-agent
```

`agentctl`, the node agent with credential identity, `ext_proc` and the MCP
gateway build for Linux and macOS (amd64 and arm64). `make check` keeps it
that way.

## 4. Run the node agent

### Linux server or CI host (cgroup identity)

```sh
sudo bin/node-agent \
  -bpf libclovisor/ebpf/agent_audit.o \
  -policy-dir /etc/clovisor/policy \
  -proxy-listen 127.0.0.1:18000 \
  -mcp-listen 127.0.0.1:18100
```

### Laptop, container or unprivileged user (credential identity)

```sh
bin/node-agent -identity credential \
  -policy-dir ~/clovisor-policy \
  -proxy-listen 127.0.0.1:18000 \
  -mcp-listen 127.0.0.1:18100
```

A node agent run as an ordinary user says so at start. The user can stop it
or edit its files, so its policy is advisory: useful for observing and
shaping agent behaviour, not for containing a hostile one.

### Directories

| | As root | As a user (Linux) | As a user (macOS) |
|---|---|---|---|
| Runtime: sockets, Envoy bootstrap, trust bundle | `/run/clovisor` (`/var/run/clovisor` on macOS) | `$XDG_RUNTIME_DIR/clovisor` | `~/Library/Application Support/Clovisor/run` |
| State: timelines, node CA, tool pins | `/var/lib/clovisor` (`/Library/Application Support/Clovisor` on macOS) | `$XDG_STATE_HOME/clovisor` or `~/.local/state/clovisor` | `~/Library/Application Support/Clovisor` |

`-runtime-dir` and `-state-dir` move them; the individual path flags (`-socket`,
`-out`, `-ca-dir`, …) override single files. `agentctl` looks for a user-level
node agent's socket first, then the system's; `CLOVISOR_SOCKET` and
`CLOVISOR_RUNS` override.

### Flags worth knowing

| Flag | Meaning |
|---|---|
| `-proxy-listen addr` | Enable the proxy. Without it runs are audited only (cgroup identity) and nothing is enforced. |
| `-mcp-listen addr` | Enable the local MCP gateway. Must be loopback. |
| `-envoy-uids 101` | Uids admitted to the `ext_proc` socket besides root and the node agent's own. Whoever can talk to `ext_proc` can write into any run's timeline. |
| `-envoy-upstream-ca file` | The trust store Envoy verifies origins with, behind termination, as Envoy sees it (a path inside its container). |
| `-proxy-non-run` | Let processes outside any run use the proxy (decided as unprofiled). Off by default. |
| `-transparent off\|audit\|enforce` | Transparent mode (§11). Needs `-proxy-listen` and cgroup identity. |
| `-transparent-port 15001` | The transparent listener's port, on `127.0.0.1` and `::1`. |
| `-transparent-stale 3s` | How long after the node agent stops its heartbeat connects are refused. |
| `-transparent-dns-port 15053` | The local resolver's port, on `127.0.0.1` and `::1`, UDP and TCP. |
| `-udp-allow ip:port,…` | UDP destinations runs may reach in transparent mode (NTP, say). All other UDP but DNS is refused. At most four. |
| `-dns-upstream ip:port,…` | Where the local resolver forwards allowed names. Default: the nameservers in `/etc/resolv.conf`. |

Signals: `SIGHUP` reloads the policy directory (a bad edit is rejected and the
policy in force stays); `SIGINT`/`SIGTERM` stop the agent, leaving live runs
running. With cgroup identity a restarted node agent resumes their timelines.
With credential identity run secrets live only in the node agent's memory:
after a restart, live runs' requests are refused and their timelines stay
partial, so restart between runs.

## 5. Run Envoy

The node agent writes `<runtime-dir>/envoy.json` and, for terminated hosts,
leaf certificates in `<runtime-dir>/envoy/tls`. The integration tests pin
**Envoy 1.34.14**; use that release or check a newer one with
`make integration ENVOY_IMAGE=…` (see §16) before upgrading.

```sh
# as root, Envoy as uid 101 (the image's user)
sudo docker run -d --name clovisor-envoy --network host \
  -v /run/clovisor:/run/clovisor envoyproxy/envoy:v1.34.14 -c /run/clovisor/envoy.json

# a user-level node agent: Envoy as the same user
docker run -d --name clovisor-envoy --network host --user "$(id -u):$(id -g)" \
  -v "$XDG_RUNTIME_DIR/clovisor:$XDG_RUNTIME_DIR/clovisor" \
  envoyproxy/envoy:v1.34.14 -c "$XDG_RUNTIME_DIR/clovisor/envoy.json"

# macOS, Envoy from Homebrew
envoy -c ~/Library/Application\ Support/Clovisor/run/envoy.json
```

Validate a bootstrap with `envoy --mode validate -c envoy.json`.

**When the set of terminated hosts changes, restart Envoy.** On reload the node
agent rewrites the bootstrap and prints `termination set is now [...]; restart
Envoy to apply it`. Until then, rules that need a terminated host's method or
path are refused rather than skipped ("needs termination").

If `ext_proc` is unreachable, Envoy fails closed: every request gets a 500.

## 6. Policy

The policy directory holds YAML files of two kinds:
- `AgentProfile`: what a run may do;
- `ProfileCeiling`: which profiles a user may ask for.

They are compiled together, because TLS posture is node-wide. A root node
agent refuses a directory or file that root does not own, or that group or
others can write. A user who could edit a ceiling could grant themselves
anything.

```yaml
# /etc/clovisor/policy/ceilings.yaml
kind: ProfileCeiling
metadata: { name: developers }
spec:
  appliesTo: { group: developers }   # or uid:, user:, gid:, any: true
  allow: [research, ci]               # profiles these callers may request
  default: research                   # granted when none is requested
  clamp: baseline                     # optional: always layered on top
```

Ceilings are matched by uid, then group, then `any`. A caller no ceiling
matches gets unprofiled runs: audited, not enforced.

```yaml
# /etc/clovisor/policy/research.yaml
kind: AgentProfile
metadata: { name: research }
spec:
  mode: enforce                # audit: decide and record would-deny, block nothing
  egress:
    default: deny
    rules:                     # first match wins
      - { name: gh, to: { fqdn: ["github.com", "*.githubusercontent.com"] }, action: allow }
      - name: gh-api-read
        to: { fqdn: ["api.github.com"], ports: [443] }
        http: { methods: [GET], paths: ["/repos/*"] }   # needs termination: see §10
        action: allow
      - name: no-paste
        to: { fqdn: ["pastebin.com"] }
        action: deny
        message: "Paste sites are blocked; put the text in the PR instead."
  mcp:
    default: deny
    servers:
      - name: github
        match: { stdio: "@modelcontextprotocol/server-github" }   # local, via the gateway
        tools: { allow: ["search_*", "get_*"], deny: ["delete_*"] }
        pin_tool_definitions: true
      - name: docs
        match: { fqdn: "mcp.example.com" }                         # remote, via the proxy
        tools: { allow: ["*"] }
    sampling: { action: deny, message: "MCP servers may not drive the model." }
```

**Profile blocks**, under `spec:`:

| Block | What it governs | Enforced by | Section |
|---|---|---|---|
| `mode` | `enforce` refuses; `audit` records what enforce would refuse | | |
| `egress` | Destinations by name, address, port, method and path, first match wins | the proxy; in transparent mode every TCP connect goes there | §10, §11 |
| `mcp` | MCP servers and their tools, sampling | the gateway and the proxy | §9 |
| `exec` | Which binaries a run may execute | BPF LSM | §11 |
| `unix` | Unix sockets outside the run | BPF LSM | §11 |
| `udp` | UDP destinations besides DNS, exact `ip:port` | the kernel, transparent mode | §11 |
| `icmp` | Ping (echo) destinations | the kernel, transparent mode | §11 |

**Ceiling fields**, under `spec:`:
- `appliesTo`;
- `allow`, `default` and `clamp`;
- `allowRootSockets`, which lets profiles under the ceiling allow sockets
  that give root;
- `udp` and `icmp`, which bound those blocks.

A profile's `udp` or `icmp` entry works only where its ceiling lists it too.

- **Explain before you load.** `agentctl explain profile.yaml…` compiles
  profiles exactly as the node agent will. It prints the *enforcement
  receipt*: for each rule, what enforces it, and the TLS posture for each
  destination. Features nothing can enforce yet are compile errors, not
  silent no-ops.
- **A `deny` needs a `message`.** The message is the narration the agent sees,
  and is how it learns to stay inside the policy.
- **Versions.** Every profile is versioned by content (`name@sha256:…`). A run
  is bound to the versions in force when it started; reloading changes only
  new runs.

## 7. Running agents

```sh
agentctl profiles                          # what you may request
agentctl run --profile research -- claude  # or any harness or command
agentctl run --profile research --mcp-config ~/.mcp.json -- my-harness
```

`agentctl run`:
- creates the run and binds the profile, resolved against your ceiling;
- with cgroup identity, moves the command into the run's cgroup before it
  executes a single instruction;
- sets the proxy variables to the run's proxy URL, in both spellings
  (`HTTP_PROXY`/`http_proxy`, `HTTPS_PROXY`/`https_proxy`), and replaces
  `NO_PROXY`;
- when hosts are terminated, points the trust variables at the node's bundle:
  `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`
  and `NODE_EXTRA_CA_CERTS`;
- with `--mcp-config`, registers the file's stdio servers with the gateway
  and writes a rewritten config for the harness to `$CLOVISOR_MCP_CONFIG`.

The run ends when the command exits, or when `agentctl` dies.

**Tool calls** (cgroup identity). A harness running inside a run can give a
tool call a cgroup of its own:

```sh
agentctl call --name run_tests -- go test ./...
```

The call runs in `run-<id>/call-<n>` under the run's policy, unchanged.
Everything it and its children do (execs, connects, DNS, proxy decisions) is
attributed to it: each timeline event carries `call`, and the timeline's
`calls` list gives each call's name, command, start, end, exit code, events
by type and refusals. The name is the harness's label, not identity. The
call's process sees its id in `CLOVISOR_CALL`. A call can be started only
from inside a run, and only subdivides it. Calls end with their command, and
anything left in their cgroup is killed. MCP servers started by the gateway
are listed among the calls as `mcp-<name>`.

**Sub-agents** (cgroup identity). `agentctl run` from inside a run starts a
nested run in `run-<parent>/run-<id>`:

```sh
agentctl run --profile research -- ./subagent.sh   # inside a run
```

The profile is requested and granted as for any run, against the user's
ceiling. The nested run's policy is then its parent's layers plus its own, so
it can never be allowed what its parent is not. That holds for egress, DNS,
Unix sockets and exec. The receipt and the timeline list the parent's layers
first, each source marked `run <parent>:`. A clamp or revoke of a run also
applies to every run nested in it, and a run that ends ends its nested runs
first.

Each nested run has a timeline of its own, with `parent` set. The parent's
timeline lists its `children`. Rules:

- The nested run's process must come from inside the parent.
- A nested run must belong to the same user as its parent.
- Runs nest at most 3 deep.
- From inside a run, `agentctl clamp` and `revoke` reach only that run and the
  runs nested in it.

The whole tree shares the top-level run's event budget, so lost and
suppressed counts appear on the top-level run's timeline. Two things are
shared across the tree:

- **Unix sockets** bound anywhere in the tree count as the run's own.
- **Network sockets**: one a parent hands to a nested run after it starts
  keeps the parent's identity at the proxy, which the parent could use
  directly anyway. One the nested run's first process already holds is
  refused at start, as for any run.

Tested clients: curl, Python requests and urllib (3.11+), and git (smart and
dumb HTTP; git authenticates to the proxy after a `407` challenge). Node's
built-in `fetch` does not read proxy variables by default. Configure the
harness's own proxy setting, or use a sandbox that forces the route.

## 8. From observation to enforcement

The adoption path, per agent workload (design §7.10):

1. **Observe.** Run the workload unprofiled, or under an `audit` profile, for
   a while. To see methods and paths on HTTPS hosts, terminate them. Use an
   audit profile whose rule for the host has `http: { paths: ["*"] }`, and an
   MCP server rule with no tool limits for each MCP server.
2. **Draft.**
   ```sh
   agentctl learn --name myagent -o myagent.yaml --all      # or run ids
   ```
   The draft allows exactly what was let through, never more:
   - Hosts seen in full get exact method and path rules. Glob suggestions
     appear as comments only.
   - Hosts used through opaque tunnels get host-level rules, with a note.
   - MCP servers get exact tool and resource lists, with pinning on.
   - Exec binaries are listed too, with interpreters flagged.
3. **Check offline.**
   ```sh
   agentctl check --profile myagent.yaml --all
   ```
   This replays the recorded runs against the draft: hosts, paths, MCP calls
   and execs. It exits 1 if anything would be denied. Review each violation:
   widen the profile, or accept the denial.
4. **Shadow live.** Install the profile with `mode: audit`, then `SIGHUP` the
   node agent. Decisions are recorded as `would-deny` and nothing is blocked.
5. **Enforce.** Set `mode: enforce` and reload. Exec rules are enforced
   only by transparent mode with BPF LSM (§11). Elsewhere an enforced
   profile's exec block needs `audit_only: true`, and the policy does not
   load without it.

## 9. MCP

**Local (stdio) servers** go through the gateway. With `--mcp-config`,
`agentctl run` registers each stdio server. The gateway refuses servers the
profile does not allow. Each allowed server is launched as the run's user;
with cgroup identity it gets a child cgroup of the run, so its egress is the
run's. The harness gets loopback HTTP URLs instead; with credential identity
those URLs carry the run's secret.

**Remote servers** are governed in the proxy. A server rule with
`match.fqdn` makes the proxy terminate that host. It then:
- inspects the JSON-RPC in each request;
- answers denied `tools/call` and `resources/read` in place;
- filters `tools/list`;
- removes server-initiated `sampling/createMessage` requests from event
  streams.

Bodies are inspected only for runs whose own profile names the host.

**Pinning.** With `pin_tool_definitions: true`, the first definition seen of
each tool is pinned, per profile and server rule, in `<state-dir>/mcp-pins.json`.
A changed definition is withheld and its calls refused (in audit mode, only
recorded) until an operator reviews it:

```sh
sudo agentctl pins                                   # tools whose definitions changed
sudo agentctl pins show research/github get_file     # pinned vs changed, and what differs
sudo agentctl pins approve research/github get_file 3f2a9c1b04de
```

Approval names the hash that `show` printed. If the server changed the tool
again in the meantime, the approval is refused. A run that already saw the
change keeps the tool blocked; runs after approval get it. Pin review is
root-only, because pins govern every run on the node.

## 10. TLS termination

A host is terminated when some rule needs what is inside TLS: `http` method
or path rules, or MCP server rules. Termination is node-wide; the receipt's
posture table lists each terminated host and the rules that caused it.
Everything else is tunnelled untouched, with the origin's own certificate.

- **Node CA.** The node CA is in `<state-dir>/ca`, with a key only the node
  agent can read. Envoy only ever gets leaf certificates. A CA within 30 days
  of expiry is replaced when the node agent starts.
- **Trust injection.** Runs trust the node CA through the variables in §7,
  pointing at `<runtime-dir>/ca-bundle.pem`, which is the system roots plus
  the node CA. Tools that read only the OS trust store, or that pin
  certificates, fail on terminated hosts. Add `no_terminate: true` to a rule
  to refuse termination for its host; rules that need termination then fail
  to compile.
- **Upstream.** Envoy verifies origins against `-envoy-upstream-ca`.
- **What crosses to origins.** The proxy strips its own annotations and the
  run's proxy credential before forwarding. Origins see an ordinary request.

Terminating TLS makes the proxy a holder of plaintext. Terminate only the
hosts whose rules need it, and treat the node as sensitive accordingly.

## 11. Transparent mode (Linux)

With the explicit proxy alone, routing is advisory: a tool that ignores the
proxy variables (Node `fetch`, `curl --noproxy`, a Go binary with its own
dialer) goes direct. Transparent mode makes routing binding. Every TCP
connect from a run is either redirected to Envoy's transparent listener or
refused, DNS goes to the node's resolver, and other UDP is refused (design
§6.5, §6.8). The policy, termination, MCP inspection and
timelines are the explicit proxy's, unchanged.

**Requirements.** Linux with cgroup v2, root, cgroup identity,
`-proxy-listen`, bpffs at `/sys/fs/bpf`, and Envoy on the host network
(`--network host`), since the transparent listener is on loopback. Run Envoy
in a container or a systemd unit of its own, so its connects can be gated
(see below).

The kernel needs BTF (`/sys/kernel/btf/vmlinux`) and the features below. By
the releases that introduced them, the floor is **5.12**. Only 7.0 (aarch64)
has been tested; run `make integration-transparent` (§16) on a kernel before
relying on it.

| Feature | Used for | Since |
|---|---|---|
| `cgroup/connect4,6`, `sockops` | redirect-or-deny, original destination | 4.17, 4.13 |
| `cgroup/sendmsg4,6` | unconnected UDP, DNS | 4.18 |
| `cgroup/recvmsg4,6`, socket storage, socket lookup from cgroup hooks | DNS replies, stashes, same-run loopback | 5.2 |
| `cgroup/getsockopt` | `SO_ORIGINAL_DST` for Envoy | 5.3 |
| `tp_btf` tracing | exec and run events | 5.5 |
| `bpf_get_current_ancestor_cgroup_id`, BPF links and link update, `INET_DIAG_CGROUP_ID` | run identity, fail-closed pins, socket lookup | 5.7 |
| `cgroup/getpeername4,6`, ring buffer | original peer, events | 5.8 |
| atomic exchange in BPF | backstop report counts | 5.12 |
| BPF LSM (`CONFIG_BPF_LSM`), active at boot | socket families, foreign sockets, Unix sockets, exec | 5.7 |
| `bpf_d_path` | exec by resolved path | 5.10 |

**Enabling BPF LSM.** Transparent mode works without it, but socket
families, foreign sockets, Unix sockets and exec are then not governed. The
receipt marks those rules "not enforced", and `agentctl status` shows
`Sockets       not active: ...`. Per-run UDP and ICMP need no LSM. To enable it:

1. Check the kernel was built with it:
   `grep CONFIG_BPF_LSM /boot/config-$(uname -r)` should print `=y`. Most
   distribution kernels are.
2. Check whether it is active: `cat /sys/kernel/security/lsm` must list
   `bpf`. If securityfs is not mounted, run
   `mount -t securityfs none /sys/kernel/security`.
3. If `bpf` is missing, add it to the `lsm=` boot parameter. Keep the
   modules already listed, in their order, and put `bpf` last. Then reboot:

   ```sh
   cat /sys/kernel/security/lsm     # e.g. lockdown,capability,landlock,yama,apparmor
   # Debian, Ubuntu: in /etc/default/grub
   GRUB_CMDLINE_LINUX="... lsm=lockdown,capability,landlock,yama,apparmor,bpf"
   sudo update-grub
   # Fedora, RHEL: grubby adds it to every installed kernel
   sudo grubby --update-kernel=ALL --args="lsm=lockdown,capability,yama,selinux,bpf"
   ```

4. After the reboot, start the node agent and check `agentctl status`. It
   should show `Sockets       enforce` (or `audit`).

Leaving out a module that was in the list turns that module off, so copy the
list exactly. BPF LSM adds no enforcement until the node agent loads its
programs. Those programs stand down for anything outside a run, and only
deny.

**Roll it out in three steps:**

1. `-transparent audit`. Nothing changes for runs. Each connect is recorded
   with what enforce would have done (`verdict` in the timeline: `would
   redirect`, `would refuse`). Replay the timelines as enforce would decide:

   ```sh
   agentctl check --transparent --udp-allow <the node's list> --profile p.yaml --all
   ```

   Besides egress rules, this decides every looked-up name as the resolver
   would (NXDOMAIN shows as a `dns` violation) and every UDP send (a `udp`
   violation unless `--udp-allow` covers it). `agentctl explain
   --transparent enforce p.yaml` shows the receipt for the transparent node.
   `agentctl learn` drafts from these timelines with notes for each of the
   above.
2. `-transparent enforce` on a test host, with real agent work.
3. `-transparent enforce` everywhere. Restart Envoy after the node agent
   starts, so it loads the bootstrap with the transparent listener.

**What happens to a connect from a run in enforce mode:**

| Destination | Outcome |
|---|---|
| The explicit proxy, the MCP gateway | Direct (exceptions). |
| Loopback, listener bound by the same run (a dev server) | Direct. |
| Loopback, nothing listening | Direct: fails with `ECONNREFUSED`, as it would anyway. |
| Loopback, a listener outside the run (a host Redis) | Redirected; the proxy refuses node-local destinations. |
| TLS with a server name | `CONNECT <name>:<port>` into the proxy. The proxy resolves the name, so a client that pairs an allowed name with another address reaches the name's address. The timeline notes the mismatch. |
| TLS without a server name; other TCP (SSH, databases) | `CONNECT <ip>:<port>`. A `cidr` rule naming the address decides. Otherwise, a hostname rule decides if the node's resolver answered that name with this address for this run, so `ssh github.com` matches a `github.com` rule on port 22. A hard-coded address with no such lookup needs a `cidr` rule. |
| Plain HTTP | Routed by `Host`, with method and path rules. |
| DNS (port 53, UDP or TCP, to any server) | To the node's resolver (below). |
| UDP to a `-udp-allow` destination, or one the run's ceiling and profile both allow (`udp.allow`) | Direct. |
| UDP on loopback, socket bound by the same run, or nothing listening | Direct. |
| Any other UDP, QUIC included | Refused with `EPERM`. Browsers and HTTP/3 clients fall back to TCP at once. Recorded once per connect, or once per unconnected socket. |
| ICMP echo from a ping socket to a destination the run's ceiling and profile both allow (`icmp.allow`) | Direct. |
| Any other packet leaving the node (other ICMP, a raw socket) | Dropped by the packet backstop. Recorded at most once a second per run, with a count. |
| Anything, while the node agent is down | Refused with `EPERM`. |

**Fail closed.** In enforce mode the connect hooks are pinned in
`/sys/fs/bpf/clovisor`, so they outlive the node agent. The node agent
writes a heartbeat only while it runs and Envoy is ready and serving the
transparent listener; it checks Envoy every second over the admin socket.
If either is down, or Envoy still runs a bootstrap from before transparent
mode, then within `-transparent-stale` every connect and DNS query from a run
is refused until both are back. A restarted node agent swaps its programs
into the pinned links with no gap.

**Check it:** `agentctl status` shows the mode, whether the node is healthy
and why not, Envoy's process and cgroup, whether the proxy is gated, and
events lost in the kernel.

```
Identity      cgroup
Transparent   enforce
Healthy       yes
Envoy ready   yes (pid 443951, cgroup /system.slice/docker-34b4….scope)
Proxy gated   yes (0 node-local connects refused)
Resolver      forwarding to 127.0.0.53:53
Active runs   0
Lost events   0
```

**The proxy's own connects are gated** whenever the proxy is on with cgroup
identity, in any transparent mode. A kernel hook on Envoy's cgroup refuses
its connects to loopback, link-local (cloud metadata) and multicast
addresses, except DNS. `ext_proc` already refuses such destinations, but it
checks a name by resolving it itself: a name that resolves differently for
Envoy a moment later (DNS rebinding) would otherwise reach the node. The
hook attaches only if Envoy's cgroup holds nothing but Envoy, as in a
container or a systemd unit of its own; otherwise `agentctl status` says why
it is not gated. It follows Envoy across restarts.

**Turning it off.** Starting the node agent with `-transparent off` (or
`audit`) removes the pins, and runs reach the network directly again.
Stopping the node agent does not: that is the fail-closed case. To remove
the hooks without a node agent, delete the pins:
`sudo rm /sys/fs/bpf/clovisor/transparent-*`.

**Runs must start clean.** The kernel applies a socket's hooks by the cgroup
it was created in, so a socket opened before the process joined the run would
bypass them. In enforce mode the run API refuses to start a run whose first
process holds network sockets (for example, a TCP socket as standard input).
Audit mode logs it instead.

**DNS.** In audit and enforce mode every DNS query from a run goes to the
node agent's resolver, whichever server the run asked; replies appear to come
from that server. The resolver:

- answers a name only if some rule in the run's profile could allow a
  connection to it, on some port, and answers NXDOMAIN otherwise, with the
  reason as an Extended DNS Error (`dig` prints it as `EDE: 15 (Blocked)`).
  A refused name never leaves the node, which is what stops DNS tunnelling.
  Audit mode answers every name and records the ones enforce would refuse;
- removes `ech` from HTTPS records, so clients send a server name the
  transparent listener can route by;
- records each query in the run's timeline, with refused names under
  `dns_blocked`;
- answers only runs: anything else gets REFUSED.

**Check `/etc/nsswitch.conf`.** If its `hosts:` line lists `resolve`
before `dns` (Fedora and others), glibc resolves through systemd-resolved's
Unix socket instead of sending DNS, and the node's resolver never sees those
lookups: runs can resolve any name, which reopens DNS tunnelling. Where BPF
LSM is active, a run with an enforcing profile cannot reach that socket
unless `unix.allow` names it, and glibc falls back to `dns`. Elsewhere, put
`dns` before `resolve` on transparent nodes, or point `/etc/resolv.conf` at
systemd-resolved's stub and drop `resolve` from the line.

A `cidr` rule does not make names resolvable, since deciding a name by what
it resolves to would mean forwarding it first. Give internal hosts `fqdn`
rules, or have the agent use addresses. DNS over HTTPS and over TLS are
ordinary connections to their servers, decided by the profile.

**Denials.** Plain HTTP and terminated hosts get the narrated 403 body. A
refused TLS or TCP connection is closed (clients report a reset); the reason
is in the timeline and the node agent's log.

In audit mode UDP and ICMP go through, and refusals are recorded as `would
refuse: UDP`; the packet backstop is off.

**UDP and ICMP per run** (milestone 4.7). A profile asks for UDP
destinations and ping targets, and the ceiling bounds them:

```yaml
# in the profile
spec:
  udp:  { allow: ["10.0.0.5:5000"] }  # exact ip:port; at most 8
  icmp: { allow: ["10.0.0.0/24"] }    # echo only; addresses or prefixes; at most 8
# in the ceiling
spec:
  udp:  { allow: ["10.0.0.5:5000"] }
  icmp: { allow: ["10.0.0.0/16"] }
```

A run gets what its ceiling and every enforcing layer of its policy all
allow, and a nested run no more than its parent. A layer without the
blocks allows none, so a clamp or revoke takes them away. `-udp-allow`
still applies to every run. Ping must use ICMP datagram sockets, which
needs `net.ipv4.ping_group_range` to cover the run's group (many
distributions set it). Raw sockets stay refused, so a ping that cannot
get a datagram socket and falls back to a raw one fails.
`learn` drafts a commented `udp:` block from refused UDP. `check` counts a
destination in the profile's `udp.allow` as allowed, provided the ceiling
grants it too.

**Sockets, where BPF LSM is active.** Runs may create IPv4, IPv6, Unix and
netlink sockets only: raw IP, packet, vsock and other families get `EPERM`.
A network socket created outside the run (inherited, or passed in over a
Unix socket) is refused at connect and send. Audit mode records these
instead. `agentctl status` shows the `Sockets` line. To turn BPF LSM on,
see "Enabling BPF LSM" above; without it these are not governed, and the
receipt says so.

**Unix sockets, where BPF LSM is active.** A run reaches Unix sockets it
created itself, and the node agent's run API. Any other Unix socket is
refused, for runs with an enforcing profile, unless the profile's `unix:`
block names it:

```yaml
spec:
  unix:
    allow:
      - "/run/user/{uid}/ssh-agent.sock"   # {uid}: the run's uid
      - "/tmp/ssh-*"                       # a trailing * matches the rest
      - "@my-abstract-name"                # an abstract socket
```

- **The address is the one the socket was bound to**, not the path the
  client used: `/dev/log` is `/run/systemd/journal/dev-log`, and
  `/var/run/docker.sock` is `/run/docker.sock` on a host where `/var/run`
  is a link. The timeline records the bound address.
- **At most eight entries.** Across clamps, a run gets the intersection.
- **Sockets that give root** (Docker, Podman, containerd, CRI-O) may be
  allowed only under a ceiling with `allowRootSockets: true`; the policy
  does not load otherwise.
- **Sockets that reach around the resolver** (systemd-resolved's varlink
  socket, and the system D-Bus) are flagged in the receipt. Learn leaves
  resolved's socket commented out.
- **Audit and runs without an enforcing profile:** each Unix socket outside
  the run is recorded once per run, under `unix` in the summary, and not
  refused. Learn drafts the `unix:` block from those records.

**Exec, where BPF LSM is active.** The kernel checks every exec in a run
with an exec policy, and again for a script's interpreter, by the path it
resolved (`/bin/true` may be `/usr/bin/gnutrue`):

```yaml
spec:
  exec:
    default: allow             # or deny: then only exec.allow runs
    require_trusted_path: true # see below
    allow:
      - { path: /usr/local/bin/terraform }
      - { path: /home/dev/project/target/* }   # everything below a directory
```

1. A path in `exec.allow` runs: an exact path, or anything below a directory
   given as `dir/*` (at most four of those).
2. Otherwise, with `require_trusted_path`, a file refused unless it and every
   directory above it are owned by root and not writable by group or
   others. Downloads, `/tmp` and home directories fail this test.
3. Otherwise `default` decides.

Every layer of a run (granted profile, clamps) must allow an exec. A refused
exec fails with `EPERM`. Each resolved path is recorded once per run with
its trust and verdict (`exec` in the summary), and learn drafts from those
paths. Audit layers and audit mode record `would refuse: exec` instead.

**Choosing `require_trusted_path`.** Turn it on for agents that run only
installed tools: anything they download or write and then run is refused.
Leave it off for coding agents that run what they build (`go test` runs
binaries from `/tmp/go-build…`, `cargo run` from `target/`), or allow their
build directories with `dir/*`. Exec rules catch unknown binaries, not
unknown behaviour: an allowed interpreter runs any code it is given (design
§7.6).

**Not covered yet:**
- a host daemon connecting on a run's behalf through a socket the profile
  allows: what the daemon does is outside the run;
- hash matching (`exec.allow[].hash`);
- per-cgroup attachment of the LSM programs (`lsm_cgroup`). The hooks are
  global and stand down outside runs.

## 12. Incident response

```sh
agentctl clamp <run-id> <profile>   # layer a narrower profile onto a live run
agentctl revoke <run-id>            # deny all further egress for a live run
```

Both only remove permissions, so the run's owner may use them as well as root.
They take effect on the next request, without restarting the run. The
timeline records who clamped and when.

## 13. Audit data

```sh
agentctl events                 # list runs
agentctl events <run-id>        # one run's timeline and summary
agentctl events --json <run-id>
```

- **Where timelines live.** Each run has a timeline in `<state-dir>/runs`,
  owned by the user who started the run and readable only by them and root.
- **What they hold.** A timeline records:
  - the bound policy layers;
  - exec, connect and DNS events, with cgroup identity;
  - every proxy decision, with method and path where the proxy saw them;
  - MCP registrations, calls and drift.

  The summary aggregates destinations, paths, tools, and denied and
  would-deny counts.
- **Event cap.** Events past the per-run cap are counted but not listed;
  summaries stay complete.
- **Lost and suppressed events.** Events the kernel could not queue (its
  buffer full) are counted per run as `lost_events`. A run that produces
  events faster than its budget has the excess counted as
  `suppressed_events` instead of reported, so one run cannot crowd out the
  others. Either marks the timeline not complete.

## 14. Security notes and limits

- **Who can reach `ext_proc`.** The `ext_proc` socket admits only root, the
  node agent's uid and `-envoy-uids`. Anything that can reach it can forge
  decisions in timelines.
- **The run API.** The run API trusts kernel peer credentials
  (`SO_PEERCRED`, or `LOCAL_PEERCRED` on macOS), never the request. A caller
  can only start runs within its own ceiling.
- **Node-local addresses.** The proxy refuses node-local destinations
  (loopback, link-local, metadata endpoints, the node's own addresses), and
  hostnames that resolve to them.
- **What the proxy cannot see.** UDP (including QUIC and DNS) never reaches
  an explicit proxy. Neither does anything that ignores the proxy variables,
  unless transparent mode (§11) is on.
  With credential identity, nothing below the proxy is observed at all. See
  design §6.8 and §11.
- **Allowed destinations.** Exfiltration through allowed destinations is a
  stated limit (design §11). Path rules narrow it; they do not close it.
- **Nested runs share their tree.** A run and the runs nested in it share
  the top-level run's event budget, its Unix sockets, and network sockets
  passed between them. A nested run can never be allowed more than its
  parent, but it can use what its parent hands it.
- **Allowed interpreters run anything.** Exec rules gate binaries: `python3`
  allowed means any Python the run writes (design §7.6).

## 15. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `cannot reach the node agent at …/agent.sock` | No node agent, or a different one: check `CLOVISOR_SOCKET`, and whether a user-level agent is running. |
| Requests get `500` from the proxy | Envoy cannot reach `ext_proc`: socket path, `-envoy-uids`, or the volume mount. |
| `unidentified client` (cgroup identity) | The client's socket is not in a run: started outside `agentctl run`, or through a proxy chain that hides the source port. |
| `407` / `no run credential` (credential identity) | The request lacked the run's proxy URL credential: started outside `agentctl run`, or the tool dropped the credentials from the proxy URL. |
| `needs termination` | A rule needs method or path on a host Envoy does not terminate yet. Restart Envoy after the reload message. |
| `426 Upgrade Required` | A bootstrap from before 2.7 with an HTTP/1.0 client (Python before 3.12). Regenerate it by restarting the node agent, then restart Envoy. |
| curl ignores the proxy for `http://` URLs | curl reads only lower-case `http_proxy`. `agentctl run` sets both; check the environment of hand-started tools. |
| TLS errors on a terminated host | The tool does not read the trust variables. Point it at `<runtime-dir>/ca-bundle.pem`, or mark the rule `no_terminate` (losing its path rules). |
| A narrated 403 body is missing | On CONNECT, clients drop the body: read the `x-clovisor-denial` response header, or the timeline. |
| MCP tools disappeared after a server update | Pin drift: `sudo agentctl pins`, review, approve. |
| A run's connects fail with `EPERM` (transparent enforce) | The node is unhealthy: `agentctl status` says why. The node agent is down, Envoy is down, or Envoy runs an old bootstrap (restart it). To drop enforcement, start the node agent with `-transparent off`. |
| `Proxy gated   no: … holds other processes` | Envoy shares its cgroup, so the rebinding guard cannot be enforced in the kernel. Run Envoy in a container or its own systemd unit. |
| A timeline has `lost_events` and `complete: false` | The kernel's event buffer was full. Its counts are lower bounds. |
| A timeline has `suppressed_events` and `complete: false` | The run produced events faster than its budget (bursts of about 1,300 execs, then about 5,000 execs or 70,000 connects a second), so the excess was not reported, to keep it from crowding out other runs. Enforcement was unaffected. |
| `holds N network sockets created outside the run` | Transparent enforce refuses runs whose first process inherited network sockets. Start `agentctl run` from a process without them. |
| A transparent TLS connection is reset | The proxy refused it: check the timeline. A TCP destination the run did not look up through the node (a hard-coded address) needs a `cidr` rule. |
| UDP tool fails with `Operation not permitted` (transparent) | UDP is refused except DNS, `-udp-allow`, and what both the ceiling's and the profile's `udp.allow` name. Check `udp_refused` and the connect events in the timeline. |
| `Name or service not known` in a run (transparent) | The resolver refused the name: no rule allows a connection to it. Check `dns_blocked` in the timeline, or `dig` for the EDE reason. |
| DNS in runs fails entirely (transparent) | The node agent is down (DNS is refused with it), or the resolver cannot reach `-dns-upstream`: see `server` and `reason` on the timeline's dns events. |

## 16. Testing a deployment

```sh
make check                               # unit tests and the macOS cross-build
DOCKER="sudo docker" make integration    # end to end in Docker
DOCKER="sudo docker" make integration-transparent  # transparent mode; Linux, privileged
```

The integration tests are self-contained once their images are built.
Credential identity needs no privileges. They start three containers:
- a local TLS origin;
- a client container with curl, Python requests and git;
- the pinned Envoy.

They check:
- path rules, narrated denials, and the headers that reach the origin;
- the 407 challenge for missing credentials;
- a git clone through termination;
- remote MCP filtering and in-place denials;
- timelines, `learn` and `check`;
- tool pin drift and its approval.

Set `CLOVISOR_IT_KEEP=1` to leave the containers up for inspection.

`make integration-transparent` runs transparent enforce mode end to end. It
needs a privileged container and clang for the BPF object. The agent
container shares the host's cgroup and PID namespaces, but keeps its runs
under a cgroup of its own (`-agents-cgroup`) and its pins in a bpffs of its
own, so a node agent already on the host is not disturbed. With clients that
ignore the proxy, it checks:

- the node's status: healthy, Envoy gated;
- HTTPS through the transparent listener, with path rules and a narrated
  denial;
- TLS to a bare address refused;
- SSH-like raw TCP allowed through the run's own lookup, and refused on a
  port the rule does not name;
- forced DNS: an allowed name resolved; an unlisted name and a
  tunnelling-shaped name refused, from glibc and Python;
- UDP refused, QUIC-shaped included, and a `-udp-allow` echo answered;
- a same-run dev server reached and a host service on loopback refused;
- a run with an inherited TCP socket refused at start;
- where BPF LSM is active: raw, packet and vsock sockets refused, netlink
  allowed, and a socket passed in after the run started refused on send;
  a Unix socket in `unix.allow` reached, another one bound outside the run
  refused, the run's own and the run API reached; a root-owned binary in
  `/tmp` refused by the trusted-path test and one under an allowed
  directory run;
- also where BPF LSM is active: a Docker socket, a live ssh-agent and
  systemd-resolved's varlink socket, all bound outside the run, refused;
- tool calls attributed to their `call-<n>` cgroups;
- a sub-agent nested in a `tp` run, requesting a broader profile, getting no
  more than `tp` allows (HTTP, DNS, exec), unable to revoke its parent, and
  revoked with it;
- per-run UDP and ping granted by profile and ceiling, refused elsewhere and
  to a sub-agent whose profile lacks them;
- `check --transparent` on the recorded runs;
- fail closed: a run already going when the node agent stops gets `EPERM`
  on its next connect and no answer to its next lookup.
