# Phase 7.0 spikes

Not production code. Results are folded into the design doc's Phase 7
section when the spikes are done.

| Path | What |
|---|---|
| `mockmodel/` | A scripted model speaking OpenAI Responses and Chat Completions, Anthropic Messages and Gemini `generateContent`, streaming or not. Its first answer calls the agent's shell tool (found by name, its arguments shaped by the tool's schema); once a tool result comes back, it answers `mock: done`. A module of its own. |
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

Not yet: Claude Code; a LangGraph server's sessions; gVisor Runtime
Monitoring; Agent Substrate.
