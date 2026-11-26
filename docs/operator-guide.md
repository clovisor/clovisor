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
| State: timelines, node CA, tool pins, counters, live runs' grants | `/var/lib/clovisor` (`/Library/Application Support/Clovisor` on macOS) | `$XDG_STATE_HOME/clovisor` or `~/.local/state/clovisor` | `~/Library/Application Support/Clovisor` |

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
| `-inspect-max-body 8388608` | The largest request body, in bytes, the proxy checks for content rules or remote MCP. Larger ones are refused with 413 (§10). |
| `-transparent off\|audit\|enforce` | Transparent mode (§11). Needs `-proxy-listen` and cgroup identity. |
| `-transparent-port 15001` | The transparent listener's port, on `127.0.0.1` and `::1`. |
| `-transparent-stale 3s` | How long after the node agent stops its heartbeat connects are refused. |
| `-transparent-dns-port 15053` | The local resolver's port, on `127.0.0.1` and `::1`, UDP and TCP. |
| `-udp-allow ip:port,…` | UDP destinations runs may reach in transparent mode (NTP, say). All other UDP but DNS is refused. At most four. |
| `-quic` | Relay QUIC (UDP 443) by server name in transparent enforce mode (§11 QUIC). Off by default: QUIC is refused and clients use TCP. |
| `-quic-port 15443` | The QUIC relay's port, on `127.0.0.1` and `::1`. |
| `-uprobes` | Record requests from the TLS plaintext of runs whose profile sets `observe.tls_plaintext` (§11 TLS plaintext): shared OpenSSL, BoringSSL and GnuTLS, and Go's `crypto/tls`. Cgroup identity; any transparent mode, or none. |
| `-uprobe-libs path,…` | The TLS libraries to probe. Default: `libssl.so.3`, `libssl.so.1.1` and `libgnutls.so.30` in the usual library directories. |
| `-dns-upstream ip:port,…` | Where the local resolver forwards allowed names. Default: the nameservers in `/etc/resolv.conf`. |

Signals: `SIGHUP` reloads the policy directory (a bad edit is rejected and the
policy in force stays); `SIGINT`/`SIGTERM` stop the agent, leaving live runs
running. With credential identity run secrets live only in the node agent's
memory: after a restart, live runs' requests are refused and their timelines
stay partial, so restart between runs.

**Restarting with cgroup identity.** Runs going across a node agent restart
keep what they were granted:
- **What is kept.** The node agent writes each live run's grants to
  `<state-dir>/grants.json` (root's, mode 0600) whenever they change: at
  start, clamp, revoke, a limit, a nested run, and the run's end. That
  covers the profile version the run was bound to, clamps, revocations and
  nesting.
- **Restoring.** A restarted node agent gives each run whose cgroup is still
  there its grants back, kernel state included, before it serves anything.
  It keeps the run on its bound version even if the policy directory changed
  meanwhile. Runs that ended meanwhile are dropped.
- **Until then, fail closed.** In transparent enforce, connects from runs are
  refused until the restore is done, and the previous node agent's exec and
  Unix socket hooks stay attached until the new ones hold the same policy.
- **A run that cannot be restored** (its profile no longer compiles on this
  node, say) is revoked, with a narrated reason, never left unprofiled.
- **Ending.** `agentctl run` reconnects to report its run's exit code. A
  restored run whose `agentctl` is gone is ended once its cgroup has been
  empty for 10 seconds.
- **Records.** `agentctl status` says what was restored at start; the run's
  timeline lists when (`restored`). Requests held for a person (§6 Ask) and
  rate allowances are not kept.

A `grants.json` that is not root's, or that others can write, stops the node
agent from starting. Move it aside to start anyway: the runs it lists then
come back unprofiled.

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
  content:                     # request bodies and query strings: see §10
    - { name: aws-keys, regex: "AKIA[0-9A-Z]{16}", action: deny }
    - { name: gh-tokens, regex: "ghp_[A-Za-z0-9]{36}", action: redact }
```

**Profile blocks**, under `spec:`:

| Block | What it governs | Enforced by | Section |
|---|---|---|---|
| `mode` | `enforce` refuses; `audit` records what enforce would refuse; `ask` is enforce, but asks a person about what the egress default would refuse | | §6 Ask |
| `egress` | Destinations by name, address, port, method and path, first match wins; a rule's `model` list limits the models its requests may name, and its `budget` the tokens and cost of its model calls | the proxy; in transparent mode every TCP connect goes there | §6 Models, §6 Budgets, §10, §11 |
| `mcp` | MCP servers and their tools, sampling (`allow`, `deny` or `ask`) | the gateway and the proxy | §9 |
| `exec` | Which binaries a run may execute | BPF LSM | §11 |
| `unix` | Unix sockets outside the run | BPF LSM | §11 |
| `udp` | UDP destinations besides DNS, exact `ip:port` | the kernel, transparent mode | §11 |
| `icmp` | Ping (echo) destinations | the kernel, transparent mode | §11 |
| `content` | Patterns in request bodies and query strings: deny, redact or record | the proxy, on hosts it terminates or that are plaintext | §10 |
| `limits` | How long a run may last, how many connections a minute, how many bytes it may send | the node agent, the proxy, the kernel | below |
| `observe` | Visibility only: `tls_plaintext` records requests from the TLS plaintext of the run's processes | uprobes, with the node's `-uprobes` | §11 TLS plaintext |

A third kind of document, `ModelPrices`, holds the node's model prices
(§6 Budgets). At most one per policy directory.

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
  destination. `AUDIT SEES` says what audit will record there: each request
  where it is terminated, the name only where it is not, and requests from
  TLS plaintext for profiles that ask, given `--uprobes` (the node's
  `-uprobes`). Features nothing can enforce yet are compile errors, not
  silent no-ops.
- **A `deny` needs a `message`.** The message is the narration the agent sees,
  and is how it learns to stay inside the policy.
- **Versions.** Every profile is versioned by content (`name@sha256:…`). A run
  is bound to the versions in force when it started; reloading changes only
  new runs.

### Limits

```yaml
  egress:
    rules:
      - name: search
        to: { fqdn: ["api.search.example"] }
        action: rate-limit             # allowed, up to the rate
        rate: { requests: 60, per: 1m }
  limits:
    duration: 30m                      # then the run ends
    connections_per_min: 120
    egress_bytes: 100Mi                # K, M, G, T or Ki, Mi, Gi, Ti
```

| Limit | Counts | Past it |
|---|---|---|
| `duration` | Time since the run that holds the profile started. | The node agent ends the run and its nested runs, killing their processes. `agentctl run` reports why. With credential identity, processes are in no cgroup: the run's proxy credential stops working instead. |
| `connections_per_min` | Connections through the proxy: each CONNECT, and each plain-HTTP request from the run. A token bucket. | A narrated `429` with `Retry-After`. |
| `rate-limit` rule | Requests that match the rule: each request inside a terminated tunnel, else each tunnel. A token bucket. | A narrated `429` with `Retry-After`. |
| `egress_bytes` | Bytes the run sends, headers included: to other hosts, and on loopback to the proxy, the MCP gateway, the transparent listener and the resolver. Loopback within the node is not counted. The kernel counts, so this needs the Linux node agent with cgroup identity. | The kernel drops any packet that would pass the limit, open tunnels included. The node agent then revokes the run's egress, so new requests are refused with a narration. |

- **Nested runs share their parent's limits.** A limit belongs to the run
  that holds the layer. A nested run inherits its parent's layers, so its
  activity counts toward its parent's limits as well as its own: a sub-agent
  cannot get a fresh allowance. A clamp with limits counts for the run it
  was applied to and the runs nested in it.
- **Audit layers record only.** A limit in an audit layer is recorded as
  what it would have done (`would end`, `would revoke`, or `would deny` on
  the request).
- **Records.** The timeline (`agentctl events <run>`) shows the bytes the
  run sent, each limit it reached and when, and why the node agent ended
  it. Refused requests appear as denials with reason `rate limit` or
  `connections_per_min`.
- **Restarts.** Byte counts are saved in `<state-dir>/counters.json` every
  few seconds, and picked up again by runs that outlive a node agent
  restart. Rate allowances start full again.

### Models

An egress rule's `model` list limits which models its requests may name.

```yaml
  egress:
    rules:
      - name: uploads                 # first: no model list
        to: { fqdn: ["api.anthropic.com"] }
        http: { paths: ["/v1/files*"] }
        action: allow
      - name: claude
        to: { fqdn: ["api.anthropic.com"] }
        model: { allow: ["claude-sonnet-5-5*", "claude-haiku-5-5*"] }
        action: allow
        message: "Use claude-sonnet-5-5 or claude-haiku-5-5."  # optional
```

- **What is read.** The JSON body's top-level `model` field, as the
  Anthropic and OpenAI APIs take it, and a `model` query parameter if the
  request has one. Entries are globs (`*`) and match without regard to case.
- **What is refused.** A request that names a model not on the list,
  with a narrated 403 that names the list (or the rule's `message`).
  Refused too, because nothing says which model they would reach:
  - a body that names no model;
  - a body that names it twice;
  - a body that is not JSON, or is compressed as anything but gzip or
    deflate.
- **What passes.** A request with no body (`GET /v1/models`) names no model
  and calls none, so it passes on the rule alone.
- **Uploads and other APIs.** File uploads and batch submissions carry no
  top-level `model`, so they would be refused. So would APIs that put the
  model in the path (Gemini, Bedrock). Give their paths a rule of their own
  above the model rule, as `uploads` does here.
- **Termination.** A model rule's hosts are terminated, as for `http` rules.
  Its body is held and checked like a content rule's (§10), and
  `no_terminate` or a `cidr` destination on a model rule is a compile error.
- **Records.** Each request a model rule decides is recorded with the model
  it named. `agentctl events <run>` lists the models by host and path, with
  refusals.
- **Learning models.** To find out which models an agent uses, observe it
  under an audit profile whose rule for the host has
  `model: { allow: ["*"] }` (§8).

### Budgets

An egress rule's `budget` bounds the tokens, and the cost in US dollars, of
the model calls it lets through, for the run holding the profile.

```yaml
  egress:
    rules:
      - name: claude
        to: { fqdn: ["api.anthropic.com"] }
        model: { allow: ["claude-sonnet-5-5*"] }
        budget: { tokens: 2000000, cost_usd: 20 }   # either, or both
        action: allow
```

Prices are node configuration, not part of a profile: a profile is what an
agent asks for, and must not set its own prices. Put one `ModelPrices`
document in the policy directory, root-owned like the rest, and reload
with `SIGHUP`:

```yaml
# /etc/clovisor/policy/prices.yaml — US dollars per million tokens
kind: ModelPrices
metadata: { name: node }
spec:
  models:                      # first match wins; * is a wildcard
    - { match: "claude-sonnet-5-5*", input: 3, output: 15, cache_read: 0.3, cache_write: 3.75 }
    - { match: "gpt-5", input: 1.25, output: 10, cache_read: 0.125 }
```

Without `cache_read` and `cache_write`, prompt-cache tokens are priced as
input.

- **What is charged.** The usage the provider reports in each response:
  - Anthropic-shaped: `input_tokens` and `output_tokens`, and cache tokens.
    Streamed, from `message_start` and the last `message_delta`.
  - OpenAI-shaped: `prompt_tokens` and `completion_tokens`, or the
    responses API's `input_tokens` and `output_tokens`, with cached tokens
    apart.

  A token budget counts every token, cache tokens included. A cost
  budget counts them at the node's prices, by the model the response
  names, or else the request.
- **What the proxy changes.**
  - It removes the request's `Accept-Encoding`, so responses arrive
    uncompressed and can be read.
  - A streamed OpenAI chat completion reports usage only if the request
    sets `stream_options.include_usage`. The proxy sets it, and takes the
    extra usage chunk out of the response again, so the client sees what
    it asked for. Requests to paths ending `/completions` are therefore
    sent without `Content-Length`.
- **When it is refused.** A request once the budget is spent, before it is
  sent: a narrated 403 with reason `budget`. Calls already in flight are
  charged as they finish, so a budget can be overrun by what they cost.
  Under a cost budget, a request naming a model the node has no price for
  is refused too, since the budget could not be kept.
- **Estimates.** A successful response with no usage the proxy can read
  (another API shape, a compressed response) is charged an estimate: a
  token per four bytes each way, flagged as estimated. An error response
  without usage is not charged. A response cut off is charged what it
  reported so far, flagged.
- **Nested runs share their parent's budget,** as for limits: a sub-agent
  cannot get a fresh one. Audit layers record a would-refuse instead.
- **Records.** Each call is a `usage` event, with its tokens, cost and the
  budget's total after it. `agentctl events <run>` lists the run's spend
  by host and model. For each budget the run owns, it shows the total,
  nested runs included, and when the budget was reached. Spending is kept
  in `<state-dir>/counters.json`, so a node agent restart does not refill
  a budget.

### Ask

`action: ask` holds a request until a person approves or denies it.

```yaml
spec:
  mode: enforce                # or ask: see below
  ask: { timeout: 2m }         # defaults for this profile's asks
  egress:
    default: deny
    rules:
      - name: packages
        to: { fqdn: ["pypi.org", "files.pythonhosted.org"] }
        action: ask
        message: "The agent wants to install a package."   # shown to whoever decides
      - name: issue-writes
        to: { fqdn: ["api.github.com"] }
        http: { methods: [POST, PATCH] }
        action: ask
        ask: { timeout: 1m, on_timeout: deny }   # deny is the default
  mcp:
    sampling: { action: ask }  # a server asking to run the model
```

Deciding, from outside the run:

```sh
agentctl pending                       # what is held, for how long, and what then
agentctl approve 3f2a9c1b              # let this request through
agentctl deny --remember 3f2a9c1b      # refuse it, and later ones like it
agentctl pending --all                 # recent decisions too
```

- **What is held.** A request through the proxy, at its headers, so
  whoever decides sees the method, host and path, not the body. A tunnel
  to a host that is not terminated is asked about once. On a terminated
  host, each request is.
- **Remembering.** `--remember` makes the decision stand for the rest of
  the run, for requests the same rule asks about on the same host. It works
  on a request that already timed out or whose client gave up. Clients
  with short timeouts (pip waits 15 seconds) often give up before anyone
  decides; approve with `--remember`, and their retry passes.
- **Timeouts.** `ask.timeout` is from 1s to 4m, by default 2m. A held
  request has no traffic, and Envoy ends a stream idle for 5 minutes.
  `on_timeout` decides then: `deny` (the default) or `allow`. A refusal
  is a narrated 403 saying whether a person declined or no one decided.
- **Who decides.** A decision grants what policy did not, so it is never
  taken from inside a run: an agent must not approve itself.
  - With cgroup identity, the run's owner or root may decide, from
    outside any run.
  - With credential identity, a run's processes are in no cgroup and run
    as its owner, so only root decides (`sudo agentctl approve`). An agent
    that itself runs as root could approve its own requests.
- **`mode: ask`** is enforce, except that what the egress default would
  refuse is asked about instead. Explicit deny rules still deny. Exec,
  Unix sockets, UDP and ping are enforced as in enforce mode, since a
  system call cannot wait for a person. In transparent mode the resolver
  does not answer names that only the default would ask about, since
  forwarding every name would open DNS tunnelling. Give such hosts an ask
  rule.
- **`sampling: ask`** holds an MCP server's request for a model
  completion. `agentctl pending` shows the start of what it asks the
  model. Denied, the server is told so; the client never sees it.
- **Limits.** The node holds at most 256 requests, 32 per run; past that,
  503 with a narration. Held requests and remembered decisions are kept in
  memory, so a node agent restart drops them, and their clients get an
  error.
- **Records.** The timeline shows each held request's outcome, who decided
  and how long it waited; audit layers record `would ask`. `agentctl
  check` lists what a profile would ask about.

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

### Coding agents

These agents are tested under Clovisor, in transparent enforce and in
explicit mode with credential identity, at the versions
`integration/agents` pins. In both modes each finished its turn, and its
model calls and its tools' requests were decided one by one.

| Agent (tested) | Runtime, TLS | Trusts the node CA | Proxy, with the run's credential | TLS plaintext (§11) |
|---|---|---|---|---|
| Claude Code 2.1.332 | Bun, BoringSSL linked in | yes | yes | not visible |
| Codex 0.172.0 | Rust, rustls | yes (reads `SSL_CERT_FILE`) | yes | not visible |
| Gemini CLI 0.71.1 | JavaScript; needs Node 20 or later | yes | yes | visible on an official Node build |
| OpenCode 1.19.6 | Bun, BoringSSL linked in | yes | yes | not visible |

So termination works for all four: path, model and content rules apply to
their model calls. Where a host is not terminated, the timeline has only
its name, except for Gemini CLI on an official Node.

**What each reaches besides its model.** A default-deny profile refuses
these. Each agent still finished its turn with them refused.

| Agent | Hosts | To quiet it |
|---|---|---|
| Claude Code | `api.anthropic.com` (even with `ANTHROPIC_BASE_URL` set), `http-intake.logs.us5.datadoghq.com` | `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`: it then reaches only its model |
| Codex | `ab.chatgpt.com`; `github.com`, from a `git ls-remote` of `openai/plugins.git` it starts | |
| Gemini CLI | `play.googleapis.com` (telemetry) | |
| OpenCode | `models.opencode.ai` (its model catalogue); `registry.npmjs.org`, to install a provider package as it runs | It works without both. |

Learn drafts them like any other destination, and the draft lists them
under their own rules, so you can keep or drop each.

**Also:**
- **Codex runs its tools through itself:** each tool command is exec'd as
  `/proc/self/exe --codex-run-as-process-setup …`, then `bash -c`. An
  `exec.allow` list must allow Codex's own binary. Its first command
  sources the run's `~/.bashrc` (`bash -lc`).
- **OpenCode installs npm packages while it runs.** Decide deliberately
  whether `registry.npmjs.org` is allowed: it is a supply-chain path.
- **Refusals reach the model.** A tool's request refused by a rule
  returns the narrated `403`. The agent's tool hands that back to the
  model, which sees the rule's `message`.

**Many sessions in one process.** A server that runs several agent
sessions in one process, a LangGraph server for instance, is one run:
one policy and one timeline for all of them (design §5.8). With credential
identity, each session can have a run of its own. The session opens a run
API connection, `create`s a run with the profile it asks for, sends
through the run's proxy URL (for example httpx's `proxy=`), and `end`s
the run when done. `spikes/phase7/langgraph/server.py` shows it in about
thirty lines (`SessionRun`). Those runs are not nested in the process's
run, so a session can ask for any profile its user's ceiling allows.

## 8. From observation to enforcement

The adoption path, per agent workload (design §7.10):

1. **Observe.** Run the workload unprofiled, or under an `audit` profile, for
   a while. To see methods and paths on HTTPS hosts, terminate them. Use an
   audit profile whose rule for the host has `http: { paths: ["*"] }`, and an
   MCP server rule with no tool limits for each MCP server. To see which
   models a run uses, give the model API's rule `model: { allow: ["*"] }`.
2. **Draft.**
   ```sh
   agentctl learn --name myagent -o myagent.yaml --all      # or run ids
   ```
   The draft allows exactly what was let through, never more:
   - Hosts seen in full get exact method and path rules. Glob suggestions
     appear as comments only.
   - Hosts used through opaque tunnels get host-level rules, with a note.
   - MCP servers get exact tool and resource lists, with pinning on.
   - Rules for a host whose models were recorded get a `model` list naming
     those models. A comment flags requests on the same paths that named
     none, which the list would refuse.
   - Exec binaries are listed too, with interpreters flagged.
3. **Check offline.**
   ```sh
   agentctl check --profile myagent.yaml --all
   ```
   This replays the recorded runs against the draft: hosts, paths, models,
   MCP calls and execs. A request a model rule would decide, from a run
   that did not record its model, is listed as not replayable. Budgets are
   not replayed, since spending depends on the order of calls and on
   prices; the report names them. It exits 1 if anything would be denied.
   Review each violation: widen the profile, or accept the denial.
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
  streams, or holds them for a person under `sampling: ask` (§6 Ask).

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
or path rules, `model` lists, budgets, MCP server rules, or content rules. Termination is node-wide; the receipt's
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

### Content rules

A content rule is a pattern (RE2, Go `regexp` syntax) checked against what
a run sends: the request body, and the query string, raw and
percent-decoded. Its action:
- `deny` refuses the request with a narrated 403 (`message`, or one
  generated), and nothing is sent;
- `redact` replaces each match in the body with `*` of the same length, so
  the request still fits its Content-Length;
- `tag-and-log` records the match and changes nothing.

```yaml
  content:
    - { name: aws-keys, regex: "AKIA[0-9A-Z]{16}", action: deny }
    - name: internal-hosts
      regex: "[a-z0-9-]{1,63}\\.corp\\.internal"
      action: redact
      to: { fqdn: ["api.openai.com"] }   # only these hosts
```

**Which hosts.** Without `to:`, a rule covers every host the profile allows
by name, and its remote MCP servers. Those hosts are terminated for it (or
stay plaintext, if allowed on port 80 only). Some hosts are left out, and
the receipt lists them under each rule:
- hosts marked `no_terminate`;
- hosts allowed only on ports that are not HTTP or TLS;
- destinations allowed by address (`cidr`);
- anything reached only through `fqdn: "*"` or `egress.default: allow`.

The proxy cannot read those requests. Check the receipt before relying on a
rule.

**How bodies are checked.** The proxy holds a covered request's body until
it is complete, checks it whole (so a match split across packets is still
found), then sends it on, redacted or not, or refuses it. What cannot be
checked is refused:
- a body over `-inspect-max-body` (default 8 MiB) gets 413;
- a body compressed as anything but gzip or deflate gets 415. Gzip and
  deflate bodies are decoded to check, but a `redact` match in one refuses
  the request, since it cannot be rewritten compressed;
- a `redact` match in the query string refuses the request;
- 503 when the node holds as many inspected requests as it allows: 4,096,
  256 per run, 256 MiB of bodies.

**Limits.**
- A rule sees bytes as sent. A secret split up, re-encoded (base64) or
  hidden in an encoding the rule does not anticipate does not match.
  Content rules narrow exfiltration through allowed hosts; they do not close
  it (design §11).
- Responses are not checked.
- Prefer bounded repetition (`{20,40}`) to `+` and `*`: one match of an
  unbounded pattern can run to the end of the body. The receipt flags it.

**Records.** Each match lands in the run's timeline as a `content` event.
The summary counts, per host and rule, the matches, refusals and
redactions, and what an audit layer would have done. The matched text is
never recorded. `agentctl check` cannot replay content rules, since
timelines do not hold what was sent, and says so.

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
| `bpf_ima_file_hash`, the TAI clock | exec by content (`exec.allow[].hash`) | 5.18, 5.19 |
| uprobe-multi links with cookies | TLS plaintext (`-uprobes`) | 6.6 |

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
| UDP 443, with `-quic` | To the node's QUIC relay, which decides the server name (below). |
| Any other UDP, QUIC without `-quic` included | Refused with `EPERM`. Browsers and HTTP/3 clients fall back to TCP at once. Recorded once per connect, or once per unconnected socket. |
| ICMP echo from a ping socket to a destination the run's ceiling and profile both allow (`icmp.allow`) | Direct. |
| Any other packet leaving the node (other ICMP, a raw socket) | Dropped by the packet backstop. Recorded at most once a second per run, with a count. |
| Anything, while the node agent is down | Refused with `EPERM`. |

**QUIC (opt-in, `-quic`).** HTTP/3 and other QUIC clients send UDP to port
443. With `-quic`, the connect hooks send it to the node agent's relay
instead of refusing it.

- **How it is decided.** The relay holds a client's first datagrams until
  their Initial packets hold the whole TLS ClientHello. Those packets are
  protected only with keys anyone can derive. It then decides the server
  name as a `CONNECT` to that name on port 443 would be decided.
- **Where it goes.** Allowed, the datagrams go on untouched to the address
  the name resolves to, never the one the client chose; the replies come
  back as if from where the client sent.
- **What is refused,** with a QUIC `CONNECTION_REFUSED` saying why, so the
  client reports it and falls back to TCP:
  - names the profile does not allow;
  - hosts whose rules need method, path, body, model or budget checks, or
    a person's approval, since those are done on terminated TCP;
  - encrypted ClientHellos (ECH), whose real name is hidden;
  - connections with no server name.

  Other QUIC versions and packets the relay cannot read get no answer; the
  client falls back after its handshake timeout.
- **Records.** Each connection is a `CONNECT` in the timeline, noted
  `QUIC to <address>`, so `learn` and `check` treat it like a TLS tunnel.
  `agentctl check --transparent --quic` replays refused UDP 443 from earlier
  runs as the relay would decide it.
- **Limits.**
  - At most 4,096 relayed connections on the node, 256 per run.
  - A connection with no traffic for 2 minutes is dropped.
  - A client that migrates to a new address loses its connection, which
    then fails and falls back.
  - Connections count toward `connections_per_min` and `egress_bytes`.

**Fail closed.** In enforce mode the connect hooks are pinned in
`/sys/fs/bpf/clovisor`, so they outlive the node agent. The node agent
writes a heartbeat only while it runs and Envoy is ready and serving the
transparent listener; it checks Envoy every second over the admin socket.
If either is down, or Envoy still runs a bootstrap from before transparent
mode, then within `-transparent-stale` every connect and DNS query from a run
is refused until both are back. A restarted node agent swaps its programs
into the pinned links with no gap, and restores live runs' grants before its
first heartbeat (§4 Restarting).

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

**Pinning a binary's content.** An exact `exec.allow` entry may carry a
`hash`, as `sha256sum` prints it. The path then runs only with that
content; anything else at that path is refused, whatever `default` and
`require_trusted_path` say. A path may be listed with up to four hashes (an
upgrade, or one per architecture), and not also without one:

```yaml
    allow:
      - path: /usr/local/bin/terraform
        hash: sha256:0f3c…               # sha256sum /usr/local/bin/terraform
      - path: /usr/local/bin/terraform
        hash: sha256:9a41…               # the next version, during the upgrade
```

- The kernel hashes the file at exec with `bpf_ima_file_hash`, which needs
  no IMA policy, and keeps the hash per inode. It reuses a hash only on
  ext4, xfs, btrfs and tmpfs, only while the inode's change time and
  version are as they were, and only for files last changed more than a
  minute before they were hashed. Elsewhere (overlay, FUSE, NFS) every exec
  of a pinned path is hashed: about 1.6 ms, 4 ms for a 10 MB binary.
  Nothing is hashed for paths without a hash.
- The timeline records each pinned path's hash (`hash` in `exec`), and
  whether the cache answered (`hash_cached`). A refusal's note names the
  content that ran. `learn` drafts the hashes recorded for paths a profile
  already pinned; for others, add the hash yourself.
- `check` decides a pinned path by its recorded hash. A run recorded before
  the path was pinned has no hash, so check lists it as unverifiable.
- A pin is updated by editing the profile: an upgraded binary is refused
  until its hash is listed.
- On a kernel without `bpf_ima_file_hash` or the TAI clock, the node agent
  loads an exec hook that decides by path alone and logs `exec hashes
  unavailable`. Enforcing profiles with hashes then fail to load, and in
  audit the receipt says the hashes are not verified. `agentctl status`
  shows which hook is in use.

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
- per-cgroup attachment of the LSM programs (`lsm_cgroup`). The hooks are
  global and stand down outside runs.

### TLS plaintext (uprobes)

For hosts the proxy does not terminate (`no_terminate`, clients that pin
certificates, nodes with no node CA in the agents' trust), the timeline
otherwise shows only the host. A profile can ask to see the requests:

```yaml
spec:
  observe: { tls_plaintext: true }
```

With `-uprobes` on the node, the node agent probes the TLS libraries of that
run's processes:
- **What is covered.**
  - OpenSSL, BoringSSL and GnuTLS as shared libraries: curl, Python, the
    distribution's Node, git (GnuTLS on Debian and Ubuntu).
  - Go's `crypto/tls` in Go binaries built with go1.21 to go1.26, on arm64
    and amd64, stripped or not: `gh`, `terraform`, the `go` command and
    other Go tools. Each Go binary a run executes is listed under
    `Programs with their own TLS` in `agentctl events`, as probed or not
    visible, with the reason (a Go version not yet tested, for instance).
  - OpenSSL linked into a binary that exports it: official Node builds
    (from nodejs.org, nvm, or the Docker `node` images), labelled with
    the OpenSSL version.
- **What is recorded.** Each request's method, host, path (without the
  query string) and status, and for MCP the JSON-RPC method and tool name.
  These go under `Seen in TLS plaintext` in `agentctl events`, and `tls` in
  the timeline. Bodies, headers and arguments are not kept.
- **It never decides.** Nothing seen this way is refused; the proxy still
  makes every decision. A run can avoid the probes by bringing its own TLS.
- **What it costs.** Only the run's processes pay: the probes are attached
  per process. Each exec in the run is held stopped until they are, about
  1 to 15 ms. Each TLS call then costs a few microseconds more, measured at
  about 5 µs in a VM. That is why it is per profile: turn it on for the runs
  you are learning from.
- **Not seen:**
  - other TLS stacks linked in: Bun-built binaries (Claude Code among
    them), rustls, OpenSSL linked in without its symbols. These are listed
    under `Programs with their own TLS` as not visible, with the reason;
  - Go binaries of other versions or architectures (listed as not
    visible);
  - a process that forks without exec (the child is not probed);
  - libraries at paths the node agent does not see (another mount
    namespace's copies).
- **learn and check.** For a host the proxy did not terminate, `learn` lists
  the paths seen and writes them as a path rule left commented out, since
  enabling it means terminating the host. `check` replays them as path rules
  would decide them.
- **Safety.** A process is held only while the node agent's heartbeat is
  fresh. One held for more than a second is continued without its probes. A
  restarted node agent continues processes left stopped in runs that
  capture, and attaches probes again to the processes already running in
  them. What they sent while no node agent was up is not seen.

`agentctl status` lists the libraries probed and the Go versions
(`TLS capture`).

## 12. Incident response

```sh
agentctl clamp <run-id> <profile>   # layer a narrower profile onto a live run
agentctl revoke <run-id>            # deny all further egress for a live run
```

Both only remove permissions, so the run's owner may use them as well as root.
They take effect on the next request, without restarting the run. The
timeline records who clamped and when.

A run waiting for approval is listed by `agentctl pending`. Refuse what it
waits for with `agentctl deny <id>`, and `--remember` to refuse the rest
like it for the run (§6 Ask). A run that has spent its budget or reached a
limit is already refused there; `agentctl events <run-id>` shows which, and
by which profile.

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
  - MCP registrations, calls and drift;
  - content rules that matched each request, by name and count, never the
    matched content;
  - the model each request a model rule decided named;
  - each budgeted call's usage and charge, flagged where estimated, and
    each rule's spend;
  - each ask, who decided it and how long it waited;
  - limits reached, and what they did (refused, revoked, ended);
  - each executable's resolved path and trust, and its SHA-256 where a
    profile pins it.

  The summary aggregates destinations, paths, tools, and denied and
  would-deny counts.
- **What audit did not see.** `Visibility` in `agentctl events` lists each
  destination of the run at the best level anything saw it, the least seen
  first, with the reason it was not seen better:

  | Level | Meaning |
  |---|---|
  | `requests` | The proxy saw each request: plain HTTP, or TLS it terminated. |
  | `plaintext` | Tunnelled, but its requests were read from the run's TLS plaintext (§11 TLS plaintext). |
  | `name` | Only the name, from the CONNECT or the SNI: tunnelled, and no plaintext seen. The reason says whether the profile asked for plaintext, and names the binaries whose TLS was not visible. |
  | `address` | Only the address the kernel saw connected to: not through the proxy (explicit mode), or UDP. A name from the run's DNS lookups is shown when there is one. |

  It is in the timeline's summary as `visibility`. Timelines from before it
  are reported from their summary.
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
  stated limit (design §11). Path rules and content rules narrow it; they
  do not close it.
- **Nested runs share their tree.** A run and the runs nested in it share
  the top-level run's event budget, its Unix sockets, and network sockets
  passed between them. A nested run can never be allowed more than its
  parent, but it can use what its parent hands it.
- **Allowed interpreters run anything.** Exec rules gate binaries: `python3`
  allowed means any Python the run writes (design §7.6).
- **Content rules match bytes as sent.** A secret re-encoded or split across
  fields gets past them (§10 Content rules). They need the host terminated,
  and they never apply to hosts marked `no_terminate`.
- **Budgets can be overrun** by calls already in flight when they run out,
  and are charged an estimate where a response carries no usage (§6
  Budgets). Prices are node configuration; a profile cannot set them.
- **Approvals come from outside the run.** The run API refuses decisions
  from inside a run or its descendants, so an agent cannot approve itself.
  With credential identity only root may decide.
- **Upgrading to Phase 6.6: restart Envoy.** Before it, while one run had a
  tunnel open to a terminated host, another run's requests inside its own
  tunnels to that host could be taken as the first run's: decided under
  its profile, and recorded in its timeline. The fix is in the Envoy
  bootstrap the node agent writes, so it takes effect only once Envoy is
  restarted on the new one.
- **TLS plaintext is the most sensitive data the node touches.** With
  `-uprobes`, the kernel copies up to 2 KB of each write and 512 bytes of
  each read made by the TLS libraries of runs that ask. The copies reach
  only the node agent, through the kernel ring buffer, and are parsed in
  its memory. Timelines keep method, host, path without the query, status,
  and an MCP call's method and tool: the same as for a terminated host. As
  timelines are, they are readable by the run's owner and root. Bodies,
  headers and tool arguments are dropped.
- **Uprobes inform; they never decide.** Nothing read from plaintext
  changes a verdict. A run can avoid the probes by carrying a TLS stack
  they do not reach (§11 TLS plaintext); `Visibility` in `agentctl events`
  shows where that happened. The proxy, which a run cannot bypass in
  transparent enforce mode, remains the only place egress is decided.

## 15. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `cannot reach the node agent at …/agent.sock` | No node agent, or a different one: check `CLOVISOR_SOCKET`, and whether a user-level agent is running. |
| Requests get `500` from the proxy | Envoy cannot reach `ext_proc`: socket path, `-envoy-uids`, or the volume mount. |
| `unidentified client` (cgroup identity) | The client's socket is not in a run: started outside `agentctl run`, or through a proxy chain that hides the source port. |
| The node agent logs `ext_proc: refused … recorded in no run` | A request the proxy could not tie to a run, or parse: the reason and the addresses follow. No timeline has it. A client address that belongs to another, or an ended, run inside a terminated tunnel points at an Envoy started from a bootstrap from before Phase 6.6: restart Envoy. |
| `407` / `no run credential` (credential identity) | The request lacked the run's proxy URL credential: started outside `agentctl run`, or the tool dropped the credentials from the proxy URL. |
| `needs termination` | A rule needs method, path or model, or a content rule covers the host, and Envoy does not terminate it yet. Restart Envoy after the reload message. |
| `413` on a large upload | The body is over `-inspect-max-body`, and a content rule, a model rule or remote MCP covers the host. Raise the limit, scope the content rule with `to:`, or give the upload's path a rule without a model list. |
| `415` from the proxy | A content or model rule covers the host and the body's `Content-Encoding` is not gzip or deflate. |
| A request hangs, then `403` "no one gave it within …" | An ask rule held it and no one decided. `agentctl pending` lists held requests; the node agent's log names each as it is held. |
| `agentctl pending` or `approve` "from inside a run" | Decisions are refused from inside any run (§6 Ask). Run it from another terminal. |
| `approve` "only root decides" | Credential identity: use `sudo agentctl approve`. |
| `503` "not held" | The node or the run holds as many requests for approval as it may. Decide some, or wait. |
| `403` "spent the budget of rule …" | The run, or the run it is nested in, has spent that rule's budget (§6 Budgets). `agentctl events` shows the spend. |
| `403` "this node has no price for model …" | The rule has a cost budget, and the node's `ModelPrices` has no entry matching the model. Add one and send `SIGHUP`. |
| A run's spend is marked `estimated` | The responses carried no usage the proxy could read: another API shape, or a compressed response. |
| `403` "not allowed by rule … Allowed: …" | The request named a model the rule's `model` list does not admit (§6 Models). |
| `403` "names no model" or "is not a JSON object" on an upload | A model rule decided a request whose body carries no top-level `model`. Give its path a rule of its own above the model rule. |
| `429` with `Retry-After` | A `rate-limit` rule or `connections_per_min` (§6 Limits). The narration names the rule or profile. |
| `agentctl: run … was ended by the node agent` | The run reached its `duration`, or its parent run did. Exit status 137 (killed). |
| A run's connections stall, then everything is refused | It reached `egress_bytes`: the kernel drops its packets, then its egress is revoked. `agentctl events <run>` shows the limit and the bytes sent. |
| `503` "inspected requests in flight" | The node or the run holds as many inspected requests as allowed. Transient. |
| curl over HTTP/2 shows `000` for a refused upload | curl 7.88 loses a refusal sent before it has sent any of its body, as for a path deny on a POST. The timeline has the refusal. |
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
| A QUIC client reports `CONNECTION_REFUSED` with a reason | The node's QUIC relay refused it (§11 QUIC); the reason says why. The client should fall back to TCP, where it is decided as usual. |
| A run is revoked with "the node agent restarted and could not restore its policy" | Its grants could not be rebuilt after a restart: the reason follows. Start the run again. |
| `grants: ... must be owned by root` at start | `<state-dir>/grants.json` has the wrong owner or mode. Fix it, or move it aside to start without restoring runs (they come back unprofiled). |
| `Seen in TLS plaintext` is missing for a run under `observe.tls_plaintext` | The node runs without `-uprobes` (the receipt says so), or the client's TLS is not a shared OpenSSL, BoringSSL or GnuTLS nor Go's `crypto/tls` nor OpenSSL exported by the binary (Bun, rustls; listed under `Programs with their own TLS`), or it forked without exec. A Go client of an untested version is listed under `Programs with their own TLS` with the reason. |
| The node agent refuses to start with `TLS capture needs uprobe-multi links (Linux 6.6)` | `-uprobes` needs Linux 6.6 or later. Run without it, or upgrade the kernel. |
| `tls: pid N held at exec for over 1s without its probes; continued` | Attaching stalled or an event was lost: that process ran unobserved. |
| A pinned binary fails with `Permission denied` after an upgrade (transparent) | Its content no longer matches the `hash` in `exec.allow`; the timeline's `exec_path` note names the content that ran. Add its `sha256sum` to the entry (up to four), then remove the old one. |
| `exec hashes unavailable` in the node agent's log | The kernel lacks `bpf_ima_file_hash` (5.18) or the TAI clock (5.19), so exec is decided by path alone and enforcing profiles with hashes do not load. |
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
- content rules: bodies denied, redacted in place and passed unchanged,
  including chunked, gzip, query strings, 2 MB bodies, the size limit, and
  concurrent uploads mixed with refusals;
- limits: a rate-limit rule's 429 and `Retry-After`, and a duration that
  ends a credential-identity run;
- model lists: an admitted model passed, others refused with the list,
  bodies naming none or two refused, gzip decoded, a GET passed, a query
  parameter checked; a run observed under `"*"` drafted into a model list,
  replayed clean, and the stricter profile's refusal found by `check`;
- budgets: usage charged from Anthropic-shaped responses, streamed and
  not, and an OpenAI-shaped stream given `include_usage` with the extra
  chunk removed; `Accept-Encoding` removed; the call past the budget
  refused before it was sent; an unpriced model refused; the spend in
  `agentctl events`;
- ask: a held request approved from outside the run, the next denied with
  `--remember` and the one after refused without asking, a request no one
  decided let through by `on_timeout: allow`, and the decisions in the
  timeline and in `agentctl pending --all`;
- `sampling: ask`: a sampling request in a remote MCP server's event
  stream held, approved and passed to the client, then denied and cut
  out while the tool call's result still arrived;
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
- UDP refused, and a `-udp-allow` echo answered;
- QUIC with `-quic`: relayed for a host rule, with a ClientHello over one
  datagram and over two; refused with a reason for a host with path rules,
  and for a name the profile does not allow, decided by the name though
  sent to an allowed address;
- a same-run dev server reached and a host service on loopback refused;
- a run with an inherited TCP socket refused at start;
- where BPF LSM is active: raw, packet and vsock sockets refused, netlink
  allowed, and a socket passed in after the run started refused on send;
  a Unix socket in `unix.allow` reached, another one bound outside the run
  refused, the run's own and the run API reached; a root-owned binary in
  `/tmp` refused by the trusted-path test and one under an allowed
  directory run; a pinned script run with its content and refused with
  other content, at a path hashed every exec (overlay) and at one the
  kernel caches (tmpfs), including a change made after it was cached;
- also where BPF LSM is active: a Docker socket, a live ssh-agent and
  systemd-resolved's varlink socket, all bound outside the run, refused;
- tool calls attributed to their `call-<n>` cgroups;
- a sub-agent nested in a `tp` run, requesting a broader profile, getting no
  more than `tp` allows (HTTP, DNS, exec), unable to revoke its parent, and
  revoked with it;
- per-run UDP and ping granted by profile and ceiling, refused elsewhere and
  to a sub-agent whose profile lacks them;
- content rules with no proxy settings: a body redacted in place and one
  refused with the rule's message, on a host terminated by the transparent
  listener; and `connections_per_min`, past which connects were refused;
- limits: a rate-limit rule's 429 on a terminated host; an upload past
  `egress_bytes` cut off in the kernel, the run revoked, and no more than the
  limit counted as sent; a `duration` that kills the run;
- a model list on a host terminated for it alone: an admitted model
  passed, another refused;
- a budget shared with a nested run: the parent's and the nested run's
  calls charged to the parent, the nested run refused by it;
- mode ask: `agentctl pending` refused from inside the run, an ask rule's
  name resolved and the default's not, and a held request approved by the
  run's owner;
- `check --transparent` on the recorded runs;
- TLS plaintext with `-uprobes`: under a profile with
  `observe.tls_plaintext`, requests from curl (three, each held at exec
  until probed), Python, git (GnuTLS) and Debian's Node recorded with their
  statuses and without query strings; a Go client and its stripped build, the second
  started through `env`, probed and their HTTP/2 requests recorded; a run
  under a profile that does not ask, not probed. With `CLOVISOR_IT_NODE`
  set to an official Node binary, its `fetch` recorded from the OpenSSL
  linked into it. With `CLOVISOR_IT_RUSTLS` set to a rustls binary (such
  as `uv`), it listed as not visible. With `CLOVISOR_IT_BUN` set to an
  app compiled with `bun build --compile` that fetches its first argument,
  its request got through and it listed as not visible.
  `CLOVISOR_IT_LOG=1` prints the node agent's log even when the checks
  pass;
- tunnel identity: while one run holds a tunnel to a terminated host
  open, another run's requests to it are its own, decided by its profile;
- agents, with `CLOVISOR_IT_AGENTS=1`: Claude Code (also with its
  nonessential traffic off), Codex, Gemini CLI and OpenCode, at the
  versions `integration/agents` pins, against a scripted model
  (`integration/mockmodel`). The pins are installed once by `npm ci`, each
  package checked against the lockfile's integrity hash, into a Docker
  volume named by the lockfile's hash. Each agent runs twice:
  - under an audit profile: it finishes its turn, its model calls and its
    tool's request are decided one by one, anything else is recorded as
    would-deny, and learn drafts a profile check finds the run within;
  - under an enforcing one: its tool's request to a refused path gets the
    narrated `403`, the narration reaches the model, and the agent
    finishes with its phoning home refused too.

  In transparent mode, each agent's own TLS stack is listed as expected
  (§11 TLS plaintext). With `CLOVISOR_IT_PYDEPS` naming a Docker volume
  of LangGraph's packages, a LangGraph server's sessions run shared, and
  in explicit mode each with a run of its own;
- restart, capturing: a Python process in a run that captures TLS
  plaintext made a request before the restart and one after; both were
  recorded, the new node agent having probed the running process again;
- restart: a run going across a node agent restart refused the same things
  after it as before (a path rule, an unlisted host and its name, an
  untrusted exec), a run revoked before it stayed revoked, `agentctl status`
  reported both restored, and `agentctl run` reported the exit code;
- fail closed: a run already going when the node agent stops gets `EPERM`
  on its next connect and no answer to its next lookup.
