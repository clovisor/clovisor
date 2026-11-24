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
)

const modelProfile = `kind: AgentProfile
metadata: { name: mp }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - name: files
        to: { fqdn: ["api.example.com"] }
        http: { paths: ["/v1/files*"] }
        action: allow
      - name: llm
        to: { fqdn: ["api.example.com"] }
        model: { allow: ["claude-sonnet-5-5*", "GPT-5"] }
        action: allow
      - { name: other, to: { fqdn: ["other.example.com"] }, action: allow }
`

func TestModelCompile(t *testing.T) {
	p, _ := Parse([]byte(modelProfile))
	c, diags := Compile(Options{Linux: true}, p)
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	var llm Placement
	for _, pl := range c.Profiles[0].Placements {
		if pl.Rule == "llm" {
			llm = pl
		}
	}
	notes := strings.Join(llm.Notes, " | ")
	if llm.EnforcedBy != "ext_proc (body: model field)" || !strings.Contains(notes, "terminated: see posture") ||
		!strings.Contains(notes, "models allowed: claude-sonnet-5-5*, GPT-5") || strings.Contains(notes, "fronting") {
		t.Errorf("placement: %+v", llm)
	}
	for _, d := range c.Posture {
		if d.Dest == "api.example.com" && (d.Posture != PostureTerminate || !strings.Contains(strings.Join(d.Why, " "), "mp (llm: model)")) {
			t.Errorf("posture: %+v", d)
		}
		if d.Dest == "other.example.com" && d.Posture != PosturePassthrough {
			t.Errorf("other posture: %+v", d)
		}
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
	llmRule := `model: { allow: ["claude-sonnet-5-5*", "GPT-5"] }`
	for doc, want := range map[string]string{
		strings.Replace(modelProfile, llmRule, `model: { allow: [] }`, 1):                 "model.allow is empty",
		strings.Replace(modelProfile, llmRule, `model: { allow: ["bad model"] }`, 1):      `model "bad model" must be letters`,
		strings.Replace(modelProfile, llmRule, llmRule+"\n        no_terminate: true", 1): "but the rule asserts no_terminate",
		strings.Replace(modelProfile, `fqdn: ["api.example.com"] }
        model`, `cidr: ["10.0.0.0/8"] }
        model`, 1): "model: needs a hostname destination",
		strings.Replace(modelProfile, llmRule+"\n        action: allow", llmRule+"\n        action: deny\n        message: no", 1): "a deny rule lets nothing through",
	} {
		if got := errOf(doc); !strings.Contains(got, want) {
			t.Errorf("want %q, got:\n%s", want, got)
		}
	}
	// A model rule elsewhere asserting no_terminate on the host: the
	// posture check reports the conflict.
	conflict := modelProfile + `      - { name: pay, to: { fqdn: ["api.example.com"] }, no_terminate: true, action: allow }
`
	if got := errOf(conflict); !strings.Contains(got, "api.example.com must be terminated for mp (files: http), mp (llm: model)") {
		t.Errorf("posture conflict: %s", got)
	}
}

func TestModelDecide(t *testing.T) {
	cp := compileContent(t, modelProfile, "")
	eff := &Effective{Layers: []Layer{{Profile: cp}}}

	// At CONNECT a model rule defers to the requests inside.
	if d := eff.Decide(Request{Host: "api.example.com", Port: 443, Phase: PhaseConnect}); !d.Deferred || d.ChecksModels() {
		t.Fatalf("connect: %+v", d)
	}
	req := func(path string) EffectiveDecision {
		return eff.Decide(Request{Host: "api.example.com", Port: 443, Method: "POST", Path: path, Phase: PhaseRequest})
	}
	if d := req("/v1/files/upload"); d.Rule != "files" || d.ChecksModels() {
		t.Errorf("files: %+v", d)
	}
	d := req("/v1/messages")
	if d.Rule != "llm" || !d.ChecksModels() || !d.Models[0].Enforced {
		t.Fatalf("messages: %+v", d)
	}
	for model, ok := range map[string]bool{
		"claude-sonnet-5-5": true, "claude-sonnet-5-5-20261001": true, "gpt-5": true, "GPT-5": true,
		"claude-opus-5-5": false, "gpt-5-mini": false, ModelMissing: false,
	} {
		if v := CheckModel(d.Models, "api.example.com", model, ""); (v.Denied == nil) != ok {
			t.Errorf("%q: %+v", model, v)
		}
	}
	v := CheckModel(d.Models, "api.example.com", "claude-opus-5-5", "")
	if !strings.Contains(v.Message, `model "claude-opus-5-5" is not allowed by rule llm of profile mp. Allowed: claude-sonnet-5-5*, gpt-5.`) {
		t.Errorf("message: %s", v.Message)
	}
	v = CheckModel(d.Models, "api.example.com", ModelMissing, "")
	if !strings.Contains(v.Message, `its body has no top-level "model" field, and rule llm of profile mp allows only`) {
		t.Errorf("missing: %s", v.Message)
	}
	if !d.Models[0].Permits("Claude-Sonnet-5-5") {
		t.Error("case")
	}
	// The single-profile decision used by check.
	pd := cp.Decide(Request{Host: "api.example.com", Port: 443, Method: "POST", Path: "/v1/messages", Phase: PhaseRequest})
	if !pd.ModelChecked() || !pd.PermitsModel("gpt-5") || pd.PermitsModel("gpt-4") {
		t.Errorf("profile decision: %+v", pd)
	}

	// An audit layer on top only records.
	audit := compileContent(t, strings.Replace(strings.Replace(modelProfile, "name: mp", "name: ma", 1), `"GPT-5"`, `"gpt-4"`, 1), "audit")
	both := eff.With(Layer{Profile: audit})
	d = both.Decide(Request{Host: "api.example.com", Port: 443, Method: "POST", Path: "/v1/messages", Phase: PhaseRequest})
	if len(d.Models) != 2 {
		t.Fatalf("layers: %+v", d.Models)
	}
	if v := CheckModel(d.Models, "api.example.com", "gpt-5", ""); v.Denied != nil || len(v.WouldDeny) != 1 || v.WouldDeny[0] != "ma" {
		t.Errorf("audit layer: %+v", v)
	}
	if v := CheckModel(d.Models, "api.example.com", "gpt-4", ""); v.Denied == nil || v.Denied.Layer != "mp" || len(v.WouldDeny) != 0 {
		t.Errorf("enforce layer: %+v", v)
	}

	// A rule message narrates the refusal.
	withMsg := compileContent(t, strings.Replace(modelProfile, `"GPT-5"] }
        action: allow`, `"GPT-5"] }
        action: allow
        message: "Use claude-sonnet-5-5."`, 1), "")
	e2 := &Effective{Layers: []Layer{{Profile: withMsg}}}
	d = e2.Decide(Request{Host: "api.example.com", Port: 443, Method: "POST", Path: "/v1/messages", Phase: PhaseRequest})
	if v := CheckModel(d.Models, "api.example.com", "x", ""); v.Message != "Use claude-sonnet-5-5." {
		t.Errorf("rule message: %q", v.Message)
	}
}
