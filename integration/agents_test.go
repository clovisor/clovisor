// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Real coding agents under Clovisor (milestones 7.0, 7.1). With
// CLOVISOR_IT_AGENTS=1, the agents pinned in integration/agents are
// installed by npm ci (each package checked against the lockfile's
// integrity hash) into a Docker volume named by the lockfile's hash, with
// the official Node of the same image, and mounted at /it/agents. The
// scripted model (integration/mockmodel) runs on the origin's port 8443.

// agentNodeImage installs the agents, and its Node, an official build,
// runs Gemini CLI.
const agentNodeImage = "node:22.23.5-bookworm"

// agentsVolume returns the Docker volume holding the pinned agents,
// installing them first if this lockfile has not been.
func (e *env) agentsVolume() string {
	t := e.t
	dir, _ := filepath.Abs("agents")
	lock, err := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(lock)
	vol := "clovisor-it-agents-" + hex.EncodeToString(sum[:])[:12]
	if e.dockerCmd("run", "--rm", "-v", vol+":/agents", agentNodeImage, "test", "-f", "/agents/.installed").Run() == nil {
		return vol
	}
	t.Logf("installing the pinned agents into volume %s", vol)
	out, err := e.dockerCmd("run", "--rm", "-v", vol+":/agents", "-v", dir+":/src:ro", agentNodeImage, "sh", "-c",
		`set -e; cp /src/package.json /src/package-lock.json /agents/; cd /agents
npm ci --no-audit --no-fund --loglevel=error
cp /usr/local/bin/node /agents/node; touch /agents/.installed`).CombinedOutput()
	if err != nil {
		t.Fatalf("installing the agents: %v\n%s", err, out)
	}
	return vol
}

// withAgents mounts the agents and starts the scripted model on the
// origin, where CLOVISOR_IT_AGENTS or CLOVISOR_IT_PYDEPS (a Docker volume
// of Python packages, for LangGraph) asks for them.
func (e *env) withAgents(agentArgs []string) []string {
	agents, py := os.Getenv("CLOVISOR_IT_AGENTS") != "", os.Getenv("CLOVISOR_IT_PYDEPS")
	if !agents && py == "" {
		return agentArgs
	}
	e.run("exec", "-d", e.name("origin"), "sh", "-c",
		"/it/bin/mockmodel -listen :8443 -cert /origin/tls.crt -key /origin/tls.key > /tmp/mock.log 2>&1")
	if agents {
		agentArgs = append(agentArgs, "-v", e.agentsVolume()+":/it/agents:ro")
	}
	if py != "" {
		agentArgs = append(agentArgs, "-v", py+":/it/pydeps:ro")
	}
	return agentArgs
}

// agentScripts run each agent against the mock: its config in a home of
// its own, the model at origin.test:8443, and the prompt in $PROMPT. A
// prologue sets $A to the agents' node_modules and $ARCH to npm's name
// for this machine.
var agentScripts = map[string]string{
	"codex": `mkdir -p $HOME/.codex && cat > $HOME/.codex/config.toml <<T
model = "mock"
model_provider = "mock"
[model_providers.mock]
name = "mock"
base_url = "https://origin.test:8443/v1"
wire_api = "responses"
env_key = "MOCK_KEY"
T
CODEX=$(ls $A/@openai/codex-linux-$ARCH/vendor/*/bin/codex $A/@openai/codex/node_modules/@openai/codex-linux-$ARCH/vendor/*/bin/codex 2>/dev/null | head -1)
cd $HOME && MOCK_KEY=x timeout 120 $CODEX exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox "$PROMPT"`,
	"gemini": `mkdir -p $HOME/.gemini && echo '{"security": {"auth": {"selectedType": "gemini-api-key"}, "folderTrust": {"enabled": false}}}' > $HOME/.gemini/settings.json
M=$A/@google/gemini-cli
cd $HOME && GEMINI_API_KEY=x GOOGLE_GEMINI_BASE_URL=https://origin.test:8443 timeout 120 /it/agents/node $M/$(/it/agents/node -p "Object.values(require('$M/package.json').bin)[0]") -m mock --yolo -p "$PROMPT"`,
	"opencode": `mkdir -p $HOME/.config/opencode && cat > $HOME/.config/opencode/opencode.json <<T
{"provider": {"mock": {"npm": "@ai-sdk/openai-compatible", "name": "mock",
   "options": {"baseURL": "https://origin.test:8443/v1", "apiKey": "x"}, "models": {"mock": {"name": "mock"}}}},
 "model": "mock/mock", "permission": {"bash": "allow", "edit": "allow"}}
T
cd $HOME && timeout 180 $A/opencode-linux-$ARCH/bin/opencode run "$PROMPT"`,
	"claude": `cd $HOME && ANTHROPIC_BASE_URL=https://origin.test:8443 ANTHROPIC_API_KEY=x timeout 120 $A/@anthropic-ai/claude-code/bin/claude.exe -p "$PROMPT" --model mock --allowedTools Bash`,
	// Claude Code with its nonessential traffic off: it then reaches only
	// its model and what its work needs.
	"claude-quiet": `cd $HOME && CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 ANTHROPIC_BASE_URL=https://origin.test:8443 ANTHROPIC_API_KEY=x timeout 120 $A/@anthropic-ai/claude-code/bin/claude.exe -p "$PROMPT" --model mock --allowedTools Bash`,
}

// agentTLS is how each agent's own TLS stack is listed in transparent
// mode (milestones 6.3, 6.4): only Gemini CLI, on the official Node, is
// probed.
var agentTLS = map[string]string{
	"codex":        `rustls \d+\.\d+\.\d+ not visible`,
	"gemini":       `OpenSSL \d+\.\d+\.\d+\w*, bundled probed`,
	"opencode":     `Bun's BoringSSL not visible`,
	"claude":       `Bun's BoringSSL not visible`,
	"claude-quiet": `Bun's BoringSSL not visible`,
}

// agentSuite is how one suite runs the agents.
type agentSuite struct {
	audit, enforce string // profiles: audit with default deny, and enforce
	prefix         string // run first: transparent mode drops the proxy variables
	transparent    bool
}

// runAgent runs one agent under profile with prompt, and returns its
// output, its run and the tool results the mock received meanwhile.
func (e *env) runAgent(t *testing.T, s agentSuite, name, profile, prompt string) (out, id, toolResults string) {
	t.Helper()
	mark := func() int {
		b, _ := e.dockerCmd("exec", e.name("origin"), "wc", "-c", "/tmp/mock.log").Output()
		n, _ := strconv.Atoi(strings.Fields(string(b) + " 0")[0])
		return n
	}
	from := mark()
	// Trust the node CA (agentctl's bundle) and the origin's own CA, for
	// whatever the proxy does not terminate.
	script := `export HOME=/tmp/agent-` + name + `; rm -rf $HOME; mkdir -p $HOME
A=/it/agents/node_modules; case $(uname -m) in aarch64) ARCH=arm64 ;; *) ARCH=x64 ;; esac
cat "$SSL_CERT_FILE" /it/test-ca.crt > /tmp/trust-` + name + `.pem
export SSL_CERT_FILE=/tmp/trust-` + name + `.pem NODE_EXTRA_CA_CERTS=/tmp/trust-` + name + `.pem
PROMPT='` + prompt + `'
` + agentScripts[name] + `
echo "agent exit $?"`
	out, id = e.agentRun(profile, s.prefix+e.script("agent-"+name, script))
	log, _ := e.dockerCmd("exec", e.name("origin"), "tail", "-c", "+"+strconv.Itoa(from+1), "/tmp/mock.log").Output()
	for _, l := range strings.Split(string(log), "\n") {
		if i := strings.Index(l, "tool-results="); i >= 0 {
			toolResults += l[i:] + "\n"
		}
	}
	return out, id, toolResults
}

// runAgents runs each agent twice. Under s.audit, which records what
// enforcement would do: the turn completes, the model calls and the tool's
// request are decided one by one, everything else is recorded as
// would-deny, and learn drafts a profile that check finds the run within.
// Under s.enforce: the tool's request to /secret is refused, the refusal's
// narration reaches the model in the tool result, and the agent finishes
// its turn with its phoning home refused too.
func (e *env) runAgents(t *testing.T, s agentSuite) {
	if os.Getenv("CLOVISOR_IT_AGENTS") == "" {
		t.Skip("CLOVISOR_IT_AGENTS unset: real agents not run")
	}
	for _, name := range []string{"codex", "gemini", "opencode", "claude", "claude-quiet"} {
		t.Run(name, func(t *testing.T) {
			out, id, results := e.runAgent(t, s, name, s.audit, "run the command")
			if id == "" || !strings.Contains(out, "mock: done") || !strings.Contains(out, "agent exit 0") {
				t.Fatalf("%s did not finish its turn under %s:\n%s", name, s.audit, out)
			}
			e.timeline(id)
			shown, _, _ := e.sh("/it/bin/agentctl events " + id)
			t.Logf("%s under %s:\n%s\ntool results:\n%s", name, s.audit, shown, results)
			// The model calls, decided one by one: the proxy terminated
			// them, so the agent trusted the node CA.
			if !regexp.MustCompile(`POST origin.test:8443/\S+ -> allow rule mock-model`).MatchString(shown) {
				t.Errorf("no model call decided per request")
			}
			if !regexp.MustCompile(`GET origin.test:443/allowed -> allow rule mock-model`).MatchString(shown) {
				t.Errorf("the tool's request was not recorded in the run")
			}
			if strings.Contains(shown, "-> deny") {
				t.Errorf("something was refused under an audit profile")
			}
			others := regexp.MustCompile(`CONNECT ([a-z0-9.-]+):\d+ -> allow \(would deny: `+s.audit+`\)`).FindAllStringSubmatch(shown, -1)
			var hosts []string
			for _, m := range others {
				hosts = append(hosts, m[1])
			}
			t.Logf("%s reached besides its model and the origin: %v", name, hosts)
			if name == "claude-quiet" && len(hosts) > 0 {
				t.Errorf("with nonessential traffic off, Claude Code reached %v", hosts)
			}
			if s.transparent && !regexp.MustCompile(agentTLS[name]).MatchString(shown) {
				t.Errorf("its own TLS is not listed as %q", agentTLS[name])
			}
			// Learned like any run: the draft covers it.
			check := "/it/bin/agentctl check --profile /tmp/drafted-" + name + ".yaml " + id
			if s.transparent {
				check = "/it/bin/agentctl check --transparent --profile /tmp/drafted-" + name + ".yaml " + id
			}
			lout, lerr, err := e.sh("/it/bin/agentctl learn --name drafted-" + name + " -o /tmp/drafted-" + name + ".yaml " + id + " && " + check)
			if err != nil {
				draft, _, _ := e.sh("cat /tmp/drafted-" + name + ".yaml")
				t.Errorf("the learned profile does not cover the run: %v\n%s%s\n%s", err, lout, lerr, draft)
			}

			out, id, results = e.runAgent(t, s, name, s.enforce, "MOCK-RUN: curl -s https://origin.test/secret")
			shown, _, _ = e.sh("/it/bin/agentctl events " + id)
			t.Logf("%s under %s:\n%s\ntool results:\n%s", name, s.enforce, shown, results)
			if !strings.Contains(out, "mock: done") || !strings.Contains(out, "agent exit 0") {
				t.Errorf("%s did not finish its turn under %s, its phoning home refused:\n%s", name, s.enforce, out)
			}
			if !regexp.MustCompile(`GET origin.test:443/secret -> deny rule no-secret`).MatchString(shown) {
				t.Errorf("the tool's request to /secret was not refused")
			}
			if !strings.Contains(results, "Agents under test may not read the secret endpoint") {
				t.Errorf("the refusal's narration did not reach the model:\n%s", results)
			}
		})
	}
}

// runLangGraph runs one LangGraph process with two concurrent sessions
// (milestone 7.0): A fetches /allowed, B /secret. Shared, both use the
// process's run. Per session, each creates a run of its own through the
// run API (credential identity), B asking for a profile that refuses
// /secret. As sessions (7.3), each mints a session inside the process's
// run, with either identity, and is nested in it. Findings are logged;
// what each mode must show is asserted.
func (e *env) runLangGraph(t *testing.T, profile, prefix string, perSession bool) {
	if os.Getenv("CLOVISOR_IT_PYDEPS") == "" {
		t.Skip("CLOVISOR_IT_PYDEPS unset: LangGraph not run")
	}
	server := "PYTHONPATH=/it/pydeps python3 /it/bin/langgraph-server.py"
	modes := []string{"shared", "default-client", "sessions"}
	if perSession {
		modes = append(modes, "per-session")
	}
	narrow := "it-session"
	if strings.HasPrefix(profile, "tp-") {
		narrow = "tp-session"
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			// The origin's own CA too, for a client that goes around the
			// proxy (default-client): whether it does is the question.
			trust := `cat "$SSL_CERT_FILE" /it/test-ca.crt > /tmp/lg-trust.pem; SSL_CERT_FILE=/tmp/lg-trust.pem `
			out, id := e.agentRun(profile, prefix+trust+server+" "+mode+" "+profile+" A=allowed B=secret="+narrow+" 2>&1")
			t.Logf("%s output:\n%s", mode, out)
			shown, _, _ := e.sh("/it/bin/agentctl events " + id)
			t.Logf("the process's run %s:\n%s", id, shown)
			sessions := regexp.MustCompile(`session ([AB]): (\{.*\})`).FindAllStringSubmatch(out, -1)
			if len(sessions) != 2 {
				t.Fatalf("sessions did not finish:\n%s", out)
			}
			for _, m := range sessions {
				var r struct {
					Run  string
					Tool []string
				}
				json.Unmarshal([]byte(m[2]), &r)
				if mode != "per-session" && mode != "sessions" {
					continue
				}
				if tl := e.timeline(r.Run); mode == "sessions" {
					expect(t, tl, `"session": true`, `"parent": "`+id+`"`)
				}
				s, _, _ := e.sh("/it/bin/agentctl events " + r.Run)
				t.Logf("session %s's run %s:\n%s", m[1], r.Run, s)
				want, other := "/allowed", "/secret"
				if m[1] == "B" {
					want, other = other, want
				}
				if !strings.Contains(s, want) || strings.Contains(s, other) {
					t.Errorf("session %s's run does not hold its own requests, and only those", m[1])
				}
				if m[1] == "B" && !strings.Contains(strings.Join(r.Tool, " "), "403") {
					t.Errorf("session B was not decided by its own profile: %v", r.Tool)
				}
			}
			if mode == "default-client" {
				t.Logf("default client: model calls through the proxy: %d", strings.Count(shown, "/v1/chat/completions"))
				return
			}
			if mode == "shared" && !(strings.Contains(shown, "/allowed") && strings.Contains(shown, "/secret")) {
				t.Errorf("the process's run does not hold both sessions' requests")
			}
		})
	}
}
