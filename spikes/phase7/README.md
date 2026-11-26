# Phase 7.0 spikes

Not production code. Results are folded into the design doc's Phase 7
section when the spikes are done.

| Path | What |
|---|---|
| `mockmodel/` | A scripted model speaking OpenAI Responses and Chat Completions, Anthropic Messages and Gemini `generateContent`, streaming or not. Its first answer calls the agent's shell tool (found by name, its arguments shaped by the tool's schema); once a tool result comes back, it answers `mock: done`. A module of its own. |
| `gvmon/` | A receiver for gVisor Runtime Monitoring's remote sink (section 3). |
| `langgraph/server.py` | One LangGraph process, several concurrent sessions, shared or each with a run of its own (section 2). |
| `../../integration/*` `agents` checks | With `CLOVISOR_IT_AGENTS` naming an npm install of the agents (and `CLOVISOR_IT_NODE` an official Node, for Gemini CLI): each agent runs under `tp-agents` (transparent) or `it-agents` (explicit), audit with default deny, against the mock on `origin.test:8443`. The mock asks for `curl https://origin.test/allowed`. Timelines are logged, not asserted. |

```sh
# Install the agents (once), into a directory the containers mount.
docker run --rm -v $PWD/agents:/out node:22-bookworm bash -c \
  'npm i -g @openai/codex @google/gemini-cli opencode-ai && cp -r $(npm root -g) /out/node_modules'
CLOVISOR_IT_AGENTS=$PWD/agents/node_modules CLOVISOR_IT_NODE=/path/to/official/node \
  DOCKER="sudo docker" make integration                     # explicit: -run TestIntegration/agents
# transparent: CLOVISOR_IT_TRANSPARENT=1 ... -run 'TestTransparent/agents$'
```

## 1. Agents (2026-11-26)

Codex 0.172.0, Gemini CLI 0.71.1 (on the official Node 22.23.5), OpenCode
1.19.6, npm installs on arm64, kernel 7.0.

**Without Clovisor**, against the mock over plain HTTP: each completed the
scripted turn (tool call, result, final answer) once:
- Codex was given the Responses API: 0.172 refuses `wire_api = "chat"`.
- Gemini CLI was given `security.auth.selectedType: gemini-api-key` and
  folder trust off, without which it overrides `--yolo`.

The tools each offers:
- Codex: 8, `exec_command` and `multi_agent_v1` among them.
- Gemini CLI: 15, `run_shell_command`, `invoke_agent` and
  `google_web_search` among them.
- OpenCode: 10, `bash`, `task` and `webfetch` among them.

**Under Clovisor**, transparent enforce (`tp-agents`) and explicit with
credential identity (`it-agents`): every agent finished its turn in both
modes, and every request was decided.

| | Codex | Gemini CLI | OpenCode |
|---|---|---|---|
| Runtime, TLS | Rust (musl, static), rustls 0.23.46 via reqwest and hyper-rustls | JavaScript on the Node that runs it | Bun, BoringSSL linked in |
| Uprobes see its own TLS | no: listed `rustls 0.23.46 not visible` | yes: `OpenSSL 3.5.9, bundled` (official Node), the model calls included | no: listed `Bun's BoringSSL not visible` |
| Trusts the node CA, so termination works | yes: rustls reads `SSL_CERT_FILE` | yes (`NODE_EXTRA_CA_CERTS`) | yes |
| Honours `https_proxy`, with the run's credential in the URL | yes | yes | yes |
| Its tool's curl | through the proxy, and seen by libssl | same | same |
| Reached besides the model (would-deny) | `github.com` (a `git ls-remote` of `openai/plugins.git`, which Codex starts), `ab.chatgpt.com` | `play.googleapis.com/log` (telemetry) | `models.opencode.ai` (model catalogue), `registry.npmjs.org` (it installs `@ai-sdk/openai-compatible` as it runs) |
| Those, in the visibility report | `github.com` plaintext (git is libssl); `ab.chatgpt.com` name only | plaintext | name only |

Findings:

- **Termination works for all three.** That includes rustls, whose trust
  store was the open question: Codex reads `SSL_CERT_FILE`. So path,
  model and content rules apply to all three agents' own traffic.
- **Every agent phones home**: analytics, telemetry, model catalogues,
  plugin repositories. A default-deny profile must list those hosts or
  mean to refuse them. Learn drafts them like any other destination.
- **OpenCode installs npm packages as it runs.** A provider package is
  fetched from `registry.npmjs.org` on first use. That is a supply-chain
  path a profile should decide on deliberately.
- **Codex runs its tools through itself.** Each tool command is exec'd as
  `/proc/self/exe --codex-run-as-process-setup …` (its sandbox helper),
  even with its sandbox bypassed, then `/bin/bash -c`. Exec rules must
  allow Codex's own binary, and the timeline's argv shows `/proc/self/exe`.
- **Codex snapshots the login shell** (`bash -lc`, sourcing `~/.bashrc`)
  before its first command: the run's dotfiles execute.
- **What uprobes add is uneven.** Gemini CLI on an official Node is fully
  visible, its telemetry included. Codex and OpenCode are visible only
  where the proxy terminates. Their phoning home, tunnelled, is a name and
  nothing more.

### Claude Code (2026-11-26)

Claude Code 2.1.332, npm install, in a container. This is not the copy
the session that built Clovisor runs in. Its npm package ships the native
binary twice (`bin/claude.exe`, and the platform package it copies it
from), 368 MB each. The spike keeps one.

- **Against the mock** (`ANTHROPIC_BASE_URL`, `--allowedTools Bash`): it
  completed the turn. It probes `HEAD /api/hello` on the base URL before
  its first call. Its request offers 12 tools: `Bash`, `Agent`,
  `Workflow` and `ScheduleWakeup` among them.
- **Under Clovisor**, transparent and explicit: it finished its turn in
  both. It honours `https_proxy` with the run's credential, and trusts
  the node CA, so its model calls are terminated and decided per request.
- **TLS:** Bun, BoringSSL linked in. It is listed `Bun's BoringSSL not
  visible`, as 6.4 inferred from the Bun runtime without examining this
  binary.
- **Reached besides the model:** `api.anthropic.com`, four connections,
  though `ANTHROPIC_BASE_URL` names the mock; and
  `http-intake.logs.us5.datadoghq.com` (telemetry). Both name only.
- **With `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`**, it reached only
  the mock and the origin. A profile can then be exact: the model
  endpoint and what the work needs.

| | Claude Code |
|---|---|
| Runtime, TLS | Bun, BoringSSL linked in |
| Uprobes see its own TLS | no |
| Trusts the node CA | yes |
| Honours `https_proxy`, with credential | yes |
| Reached besides the model | `api.anthropic.com`, Datadog logs; none with nonessential traffic off |

## 2. Many sessions in one process: LangGraph (2026-11-26)

`langgraph/server.py`: one process, two sessions in threads, each a
prebuilt ReAct agent (LangGraph 1.2.24, langchain-openai 1.8.5, httpx
0.28.1) whose tool works in-process. Session A fetches `/allowed`; B
fetches `/secret`, and in per-session mode asks for `it-session`, which
refuses `/secret`. The Python packages are in a Docker volume
(`CLOVISOR_IT_PYDEPS`), not in the test image.

| Mode | What Clovisor saw |
|---|---|
| **shared**, transparent (cgroup identity) | One run, one process (one pid) for both sessions: their model calls and fetches in one timeline, under one profile, told apart only by path. Python's libssl is probed, so plaintext shows the requests too, but not whose they are. |
| **shared**, explicit (one credential) | The same: one run for both. |
| **default-client**, explicit | langchain-openai warns that its HTTP transport "disables httpx's proxy auto-detection". Here it did not: the model calls went through the proxy and were decided. The warning is not a bypass in this version. |
| **per-session**, explicit (credential identity) | **Works today, without new code.** Each session opens a run API connection, `create`s a run with the profile it asks for, and sends through that run's proxy URL (httpx `proxy=`). It `end`s the run when done. Two timelines, each with only its session's requests. B's `/secret` was refused under `it-session` (403), while A's `/allowed` passed under `it-agents`. |

Findings:

- **Per-process identity gives a server one run.** That is what §5.8 says.
  Sessions share the policy, the timeline and the budgets. A run's
  records can say what the process did, not which session did it.
- **Credential identity already splits sessions**, for a framework that
  lets each session set its proxy. That is an HTTP client per session
  (langchain-openai's `http_client`, httpx `proxy=`), and a run API
  connection held for the session's life. The adapter is about thirty
  lines, `SessionRun` in the spike.
- **But the sessions' runs are not nested in the process's run.** With
  credential identity there is no cgroup to nest by, so a session can ask
  for any profile its user's ceiling allows, escaping the process's own
  clamps. The receipt already says credential identity is a claim. For
  sessions that is the gap.
- **Under cgroup identity (transparent mode) nothing splits a process.**
  Sessions need a label the proxy can trust within the run. The shape
  that fits is **sessions as nested runs known by credential inside a
  cgroup run**:
  1. A run API op, from inside a run, mints a session: a nested run with
     no process of its own, and a credential.
  2. The session sends through the explicit proxy with that credential.
     Transparent mode still sends everything else to the proxy, so
     nothing goes around it.
  3. The proxy knows the cgroup run first. It accepts a session's
     credential only from a socket in that run's cgroup. It decides by the
     session's effective policy, which is the run's and the session's
     together, and so can only narrow.
  4. Without the credential, a request is the run's, as today.

  This is a 7.x design item. The adapter on the framework's side is
  unchanged from the credential case.

## 3. gVisor Runtime Monitoring (2026-11-26)

gVisor release-20261123.1 (`runsc`, from the release tarball, SHA-512
checked). `gvmon/` is the remote sink's server end, on gVisor's own
`wire` and `points` packages: it answers each sandbox's handshake and
prints each point as JSON. It is a module of its own, needing Go 1.27
for gVisor's. Sandboxes ran with `sudo runsc --pod-init-config=session.json
--network=none do -- …`, without changing Docker's configuration. The
session enabled `container/start`, `sentry/clone`, `sentry/execve` (with
`binary_info` and `binary_sha256`), `sentry/task_exit`, `syscall/socket`
and `syscall/connect` (enter and exit), each with the context fields
time, thread and group ids, `container_id`, credentials, cwd, process
name and parent.

| Question | Result |
|---|---|
| What arrives | Everything Phase 1's kernel audit records, from inside the sandbox. The process tree (start, clone, exec, exit, with pid and parent pid). Each exec's resolved binary path, full argv and SHA-256. Each socket and connect, the raw sockaddr (e.g. AF_INET `10.1.2.3:443`), and the result at exit (`ENETUNREACH`, `EINPROGRESS`). Uid, cwd and process name on every event. 1,040 points in all. |
| Attribution | Every event names the sandbox's container id. One receiver serves many sandboxes, a connection each. |
| Latency | 16 to 407 µs from the point to the receiver, 74 µs median, in a VM. |
| Can it refuse anything | **No.** The sink's socket is non-blocking. A point the receiver cannot take in time is retried, then dropped and counted (`DroppedCount` in the next header). It observes; it cannot decide. |
| Without a receiver | **The sandbox does not start** (`cannot init config: connect(…): connection refused`). Monitoring is fail-closed at start, and fail-open after: a receiver that dies leaves sandboxes running, their points dropped. |

Findings:

- **It is the kernel audit for gVisor.** It covers what Clovisor's BPF
  audit sees on a node: execs with paths, argv and hashes; connects; the
  tree. It does so inside a sandbox that BPF cannot see into. A 7.5 audit
  source is feasible: points mapped to timeline events, attributed by
  container id.
- **It is audit only.** Exec gating, socket-family and Unix-socket rules,
  the things Clovisor's BPF LSM enforces, cannot be enforced through it.
  In a gVisor sandbox, enforcement stays with gVisor's own configuration
  and Substrate's egress.
- **Container id to Actor is the open question.** Substrate's Worker Pods
  run the sandboxes, so the mapping from a sandbox's container id to an
  Actor, and whether a trace session survives an Actor's checkpoint and
  restore on another Worker, are for the Substrate spike.
- **A receiver must be up before any sandbox starts,** since the sandbox
  refuses otherwise. On Kubernetes that is a node-level service, like the
  node agent.

## 4. Agent Substrate (2026-11-26)

Substrate at `7319f1af` (main, shallow clone), on kind (Kubernetes
v1.37.0), arm64, no `/dev/kvm`, so gVisor only. It was set up as its
README says (`hack/create-kind-cluster.sh`, `ate-setup deploy ate-system`,
`ate-setup deploy demo egress`), in `~/clovisor-p7-work`, with three
adjustments for this host:
- a `docker` shim that runs `sudo docker`, since this user is not in the
  `docker` group;
- the buildx plugin in a private Docker config directory, since Ubuntu's
  Docker 29.1.3 has none and the installer builds with
  `docker buildx build --push`;
- `TMPDIR` and `GOTMPDIR` off `/tmp`, for its quota.

Thirteen components came up on one node in about 2.6 GB: API server,
controller, identity provider, `atelet`, router, `atenet-egress`,
Postgres, object storage, and an OpenTelemetry stack.

**Egress, as the demo runs it.** An Actor's fetch of an in-cluster target
returned 200. nftables in the Worker sends the Actor's connects to
atunnel, which opens mTLS to the egress gateway with the Actor's
certificate (`spiffe://substrate-actor.local/worker-for-actor/<atespace>/<actor>`)
and sends a CONNECT. The gateway is one Deployment for the cluster: the
target saw the gateway Pod's address. Its Envoy (1.39.5) calls Substrate's
`ext_proc` (`cmd/atenet/internal/router/egress`) on three filter chains:
- `egress`, the CONNECT. The certificate chain arrives in
  `x-forwarded-client-cert`. The `ext_proc` verifies it again against the
  actor-identity CA, reads the Actor from the SPIFFE URI, checks the
  Actor's UID is running, and answers with dynamic metadata (SNI rules,
  the dialed port) that the rest of the Envoy config uses.
- `egress-tls-mitm`, requests inside a tunnel the gateway terminates.
- `egress-cleartext`, plain HTTP.

Inside a tunnel, the Actor is read from filter state
(`dev.ate.actor.identity`). Nothing the Actor writes counts toward its
identity.

Findings:

- **Substrate solved Clovisor's 6.6 identity bug the same way, with the
  right object.** Its tunnels carry identity as filter state too. Its
  xDS notes that the tunnel key "is the only hashable value and Envoy
  pools tunnels by it, so a tunnel only carries one actor and port". It is
  set with `envoy.hashable_string`, which Envoy 1.34 (Clovisor's) lacks
  and 1.39 has. 7.2 should move Clovisor to Envoy 1.39 or later, and key
  its pools with that object instead of `upstream_server_name`.
- **An Actor is a run.** Its UID stays the same across suspend, resume and
  a move to another Worker Pod: the demo Actor came back on
  `…-bzw45` after `…-vjtq7`. Its sandbox's state path
  (`/var/lib/ate/actors/<uid>/`) moves with it. A Clovisor timeline keyed
  by the Actor spans all of that, with nothing kernel-side to restore
  (7.3).
- **There is no hook for another policy point in Envoy mode.** The egress
  chains' `ext_proc` filter is Substrate's own, and its answers carry
  metadata the rest of the config depends on. The ways in:
  1. **A second `ext_proc` on the egress chains**, after Substrate's,
     reading the identity Substrate has verified (the SPIFFE URI on the
     CONNECT, the filter state inside). Clovisor's `ext_proc` would add
     its decisions, narration and records. That needs a change to
     Substrate's xDS (`cmd/atenet/internal/router/xds.go`): an upstream
     proposal, or a local patch for the next spike.
  2. **Replacing Substrate's `ext_proc`**: Clovisor would have to
     reproduce its identity checks, policy metadata and credential
     injection. Not worth it.
  3. **agentgateway mode**, with its built-in `substrateEgress` policy:
     the same question there.
  4. **Substrate's forwarding protocol** (their #124 and #338), once
     settled.

  Option 1 fits the plan's decision not to depend on unsettled protocol:
  it touches only Envoy's `ext_proc`, which Clovisor already speaks.
- **Runtime Monitoring needs Substrate's help.** `ateworker-gvisor`, in
  each Worker Pod, starts one `runsc-sandbox` per Actor. It has no option
  for a trace session (`--pod-init-config`). Every sandbox's container id
  is the generic `_sandbox`, so the Actor would be told by its UID in the
  sandbox's root path, or by a socket per Actor. A sandbox restored from
  a snapshot would need the session again on restore. 7.5 needs an
  upstream change.

The cluster, its registry and the demo are still running. They are torn
down with `ate-setup delete all` and `hack/delete-kind-cluster.sh`.
