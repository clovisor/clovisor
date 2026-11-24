// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"strings"
	"testing"
	"time"
)

const askProfile = `kind: AgentProfile
metadata: { name: ap }
spec:
  mode: enforce
  ask: { timeout: 1m }
  egress:
    default: deny
    rules:
      - name: pypi
        to: { fqdn: ["pypi.org"] }
        action: ask
        message: "The agent wants to install a package."
      - name: writes
        to: { fqdn: ["api.github.com"] }
        http: { methods: [POST] }
        action: ask
        ask: { timeout: 30s, on_timeout: allow }
      - { name: gh, to: { fqdn: ["api.github.com"] }, action: allow }
      - { name: no-evil, to: { fqdn: ["evil.example"] }, action: deny, message: "No." }
  mcp:
    default: allow
    servers:
      - { name: fs, match: { stdio: "fs-server" } }
    sampling: { action: ask }
`

func TestAskCompile(t *testing.T) {
	cp := compileContent(t, askProfile, "")
	rules := map[string]Placement{}
	for _, p := range cp.Placements {
		rules[p.Rule] = p
	}
	if n := strings.Join(rules["pypi"].Notes, " | "); !strings.Contains(n, "held for a person's decision (agentctl pending, approve, deny); after 1m0s, deny") ||
		!strings.Contains(n, "asked once per tunnel") {
		t.Errorf("pypi placement: %s", n)
	}
	if n := strings.Join(rules["writes"].Notes, " | "); !strings.Contains(n, "after 30s, allow") {
		t.Errorf("writes placement: %s", n)
	}
	if n := strings.Join(rules["mcp/sampling"].Notes, " | "); !strings.Contains(n, "the server's request is held for a person's decision") {
		t.Errorf("sampling placement: %s", n)
	}

	errOf := func(doc string) string {
		p, err := Parse([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		_, diags := Compile(Options{Linux: true}, p)
		var b strings.Builder
		for _, d := range diags {
			b.WriteString(d.Error() + "\n")
		}
		return b.String()
	}
	for doc, want := range map[string]string{
		strings.Replace(askProfile, "timeout: 30s", "timeout: 10m", 1):                                                                               "ask.timeout must be between 1s and 4m0s",
		strings.Replace(askProfile, "timeout: 30s", "timeout: soon", 1):                                                                              `ask.timeout "soon" is not a duration`,
		strings.Replace(askProfile, "on_timeout: allow", "on_timeout: maybe", 1):                                                                     "ask.on_timeout must be deny or allow",
		strings.Replace(askProfile, "action: allow }\n      - { name: no-evil", "action: allow, ask: { timeout: 1m } }\n      - { name: no-evil", 1): "ask: is only valid with action ask",
		strings.Replace(askProfile, "sampling: { action: ask }", "sampling: { action: deny, message: x, ask: {} }", 1):                               "mcp.sampling: ask: is only valid with action ask",
	} {
		if got := errOf(doc); !strings.Contains(got, want) {
			t.Errorf("want %q, got:\n%s", want, got)
		}
	}
}

func TestAskDecide(t *testing.T) {
	cp := compileContent(t, askProfile, "")
	eff := &Effective{Layers: []Layer{{Profile: cp}}}

	d := eff.Decide(Request{Host: "pypi.org", Port: 443, Phase: PhaseConnect})
	if d.Action != ActionAsk || !d.Asks() || !d.Allowed() || d.AskHits[0].Rule != "pypi" ||
		d.AskHits[0].Message != "The agent wants to install a package." {
		t.Fatalf("pypi: %+v", d)
	}
	if to, allow := d.AskTimeout(); to != time.Minute || allow {
		t.Errorf("pypi timeout: %v %v", to, allow)
	}
	// A method rule defers at CONNECT, and asks for the request.
	if d := eff.Decide(Request{Host: "api.github.com", Port: 443, Phase: PhaseConnect}); !d.Deferred || d.Asks() {
		t.Errorf("github connect: %+v", d)
	}
	d = eff.Decide(Request{Host: "api.github.com", Port: 443, Method: "POST", Path: "/x", Phase: PhaseRequest})
	if to, allow := d.AskTimeout(); !d.Asks() || to != 30*time.Second || !allow {
		t.Errorf("github POST: %+v", d)
	}
	if d := eff.Decide(Request{Host: "api.github.com", Port: 443, Method: "GET", Path: "/x", Phase: PhaseRequest}); d.Asks() || d.Action != ActionAllow {
		t.Errorf("github GET: %+v", d)
	}
	// An ask rule's name resolves: the request is decided later.
	if d := eff.DecideName("pypi.org"); !d.Allowed() {
		t.Errorf("pypi name: %+v", d)
	}
	// Sampling.
	if d := eff.DecideMCP(MCPRequest{Kind: "sampling", Server: "fs", Argv: []string{"fs-server"}}); !d.Asks() ||
		!strings.Contains(d.AskHits[0].Message, "asks for a model completion") {
		t.Errorf("sampling: %+v", d)
	}

	// An enforcing deny in another layer wins; an audit layer's ask is
	// only recorded.
	strict := compileContent(t, `kind: AgentProfile
metadata: { name: strict }
spec:
  mode: enforce
  egress: { default: deny, rules: [] }
`, "")
	if d := eff.With(Layer{Profile: strict}).Decide(Request{Host: "pypi.org", Port: 443, Phase: PhaseConnect}); d.Allowed() || d.Layer != "strict" {
		t.Errorf("deny over ask: %+v", d)
	}
	audit := compileContent(t, strings.Replace(askProfile, "name: ap", "name: aa", 1), "audit")
	d = (&Effective{Layers: []Layer{{Profile: audit}}}).Decide(Request{Host: "pypi.org", Port: 443, Phase: PhaseConnect})
	if d.Asks() || d.Action != ActionAllow || len(d.WouldAsk) != 1 {
		t.Errorf("audit ask: %+v", d)
	}
}

func TestModeAsk(t *testing.T) {
	cp := compileContent(t, strings.Replace(askProfile, "mode: enforce", "mode: ask", 1), "")
	eff := &Effective{Layers: []Layer{{Profile: cp}}}
	d := eff.Decide(Request{Host: "unlisted.example", Port: 443, Phase: PhaseConnect})
	if !d.Asks() || d.AskHits[0].Rule != "" || !strings.Contains(d.AskHits[0].Message, "No rule in profile ap allows unlisted.example:443") {
		t.Fatalf("default: %+v", d)
	}
	if to, _ := d.AskTimeout(); to != time.Minute {
		t.Errorf("spec.ask timeout: %v", to)
	}
	// An explicit deny still denies; the default's names do not resolve.
	if d := eff.Decide(Request{Host: "evil.example", Port: 443, Phase: PhaseConnect}); d.Allowed() || !d.Enforced {
		t.Errorf("explicit deny: %+v", d)
	}
	if d := eff.DecideName("unlisted.example"); d.Allowed() {
		t.Errorf("default name resolved: %+v", d)
	}
	if !cp.Enforcing() {
		t.Error("mode ask not enforcing")
	}
	var pl *Placement
	for i := range cp.Placements {
		if cp.Placements[i].Rule == "(mode ask)" {
			pl = &cp.Placements[i]
		}
	}
	if pl == nil || !strings.Contains(strings.Join(pl.Notes, " "), "explicit deny rules still deny") {
		t.Errorf("receipt: %+v", pl)
	}
}
