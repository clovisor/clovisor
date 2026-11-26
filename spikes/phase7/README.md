# Phase 7.0 spikes

Not production code. Results are folded into the design doc's Phase 7
section when the spikes are done.

| Path | What |
|---|---|
| `mockmodel/` | A scripted model speaking OpenAI Responses and Chat Completions, Anthropic Messages and Gemini `generateContent`, streaming or not. Its first answer calls the agent's shell tool (found by name, its arguments shaped by the tool's schema); once a tool result comes back, it answers `mock: done`. A module of its own. |
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

Not yet: gVisor Runtime Monitoring; Agent Substrate.
