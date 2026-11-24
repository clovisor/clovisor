// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"math"
	"strings"
	"testing"
)

const budgetProfile = `kind: AgentProfile
metadata: { name: bp }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - name: llm
        to: { fqdn: ["api.example.com"] }
        budget: { tokens: 1000, cost_usd: 2.5 }
        action: allow
      - { name: other, to: { fqdn: ["other.example.com"] }, action: allow }
`

func TestBudgetCompile(t *testing.T) {
	cp := compileContent(t, budgetProfile, "")
	var pl Placement
	for _, p := range cp.Placements {
		if p.Rule == "llm" {
			pl = p
		}
	}
	notes := strings.Join(pl.Notes, " | ")
	if pl.EnforcedBy != "ext_proc (response: usage)" || !strings.Contains(notes, "budget: 1000 tokens and $2.50 at the node's prices") ||
		!strings.Contains(notes, "no price for") || strings.Contains(notes, "fronting") {
		t.Errorf("placement: %+v", pl)
	}
	p, _ := Parse([]byte(budgetProfile))
	c, _ := Compile(Options{Linux: true}, p)
	for _, d := range c.Posture {
		if d.Dest == "api.example.com" && (d.Posture != PostureTerminate || !strings.Contains(strings.Join(d.Why, " "), "bp (llm: budget)")) {
			t.Errorf("posture: %+v", d)
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
	b := "budget: { tokens: 1000, cost_usd: 2.5 }"
	for doc, want := range map[string]string{
		strings.Replace(budgetProfile, b, "budget: {}", 1):                                                             "budget needs tokens, cost_usd or both",
		strings.Replace(budgetProfile, b, "budget: { tokens: -1 }", 1):                                                 "budget.tokens must be between",
		strings.Replace(budgetProfile, b, "budget: { cost_usd: -3 }", 1):                                               "budget.cost_usd must be a positive amount",
		strings.Replace(budgetProfile, b, b+"\n        no_terminate: true", 1):                                         "but the rule asserts no_terminate",
		strings.Replace(budgetProfile, b+"\n        action: allow", b+"\n        action: deny\n        message: x", 1): "a deny rule lets nothing through",
	} {
		if got := errOf(doc); !strings.Contains(got, want) {
			t.Errorf("want %q, got:\n%s", want, got)
		}
	}
}

func TestBudgetDecide(t *testing.T) {
	cp := compileContent(t, budgetProfile, "")
	eff := &Effective{Layers: []Layer{{Profile: cp}}}
	if d := eff.Decide(Request{Host: "api.example.com", Port: 443, Phase: PhaseConnect}); !d.Deferred || d.ChargesBudgets() {
		t.Fatalf("connect: %+v", d)
	}
	d := eff.Decide(Request{Host: "api.example.com", Port: 443, Method: "POST", Path: "/v1/messages", Phase: PhaseRequest})
	if len(d.Budgets) != 1 {
		t.Fatalf("decision: %+v", d)
	}
	bc := d.Budgets[0]
	if bc.Key() != "bp/llm" || bc.Tokens != 1000 || bc.CostUSD != 2.5 || !bc.Enforced || bc.Profile != cp || bc.Describe() != "1000 tokens and $2.50" {
		t.Errorf("check: %+v", bc)
	}
	if bc.Spent(999, 2.49) || !bc.Spent(1000, 0) || !bc.Spent(0, 2.5) {
		t.Error("Spent")
	}
	audit := compileContent(t, strings.Replace(budgetProfile, "name: bp", "name: ba", 1), "audit")
	d = eff.With(Layer{Profile: audit}).Decide(Request{Host: "api.example.com", Port: 443, Method: "POST", Path: "/", Phase: PhaseRequest})
	if len(d.Budgets) != 2 || d.Budgets[1].Enforced || d.Budgets[1].Key() != "ba/llm" {
		t.Errorf("layers: %+v", d.Budgets)
	}
	if d := eff.Decide(Request{Host: "other.example.com", Port: 443, Method: "POST", Path: "/", Phase: PhaseRequest}); d.ChargesBudgets() {
		t.Error("other host charged")
	}
}

func TestPrices(t *testing.T) {
	p, err := ParsePrices([]byte(`kind: ModelPrices
metadata: { name: node }
spec:
  models:
    - { match: "claude-sonnet-5-5*", input: 3, output: 15, cache_read: 0.3, cache_write: 3.75 }
    - { match: "gpt-5", input: 1.25, output: 10 }
    - { match: "*", input: 100, output: 100 }
`))
	if err != nil {
		t.Fatal(err)
	}
	sonnet, ok := p.Price("Claude-Sonnet-5-5-20261001")
	if !ok || sonnet.Input != 3 {
		t.Fatalf("sonnet: %+v %v", sonnet, ok)
	}
	u := Usage{Input: 1000, Output: 2000, CacheRead: 10000, CacheWrite: 1000}
	if got, want := u.Cost(sonnet), (1000*3+2000*15+10000*0.3+1000*3.75)/1e6; math.Abs(got-want) > 1e-12 {
		t.Errorf("cost %v, want %v", got, want)
	}
	gpt, _ := p.Price("gpt-5")
	// Without cache prices, cache tokens are priced as input.
	if got, want := (Usage{Input: 1, CacheRead: 1}).Cost(gpt), 2*1.25/1e6; math.Abs(got-want) > 1e-15 {
		t.Errorf("gpt cost %v", got)
	}
	if other, _ := p.Price("gpt-5-mini"); other.Input != 100 {
		t.Errorf("first match: %+v", other)
	}
	if u.Tokens() != 14000 {
		t.Errorf("tokens %d", u.Tokens())
	}
	var none *ModelPrices
	if _, ok := none.Price("gpt-5"); ok {
		t.Error("nil list priced")
	}
	for doc, want := range map[string]string{
		"kind: ModelPrices\nspec: { models: [] }\n":                                "spec.models is empty",
		"kind: ModelPrices\nspec: { models: [{ match: \"a b\", input: 1 }] }\n":    "must be letters",
		"kind: ModelPrices\nspec: { models: [{ match: a, input: -1 }] }\n":         "prices must be zero or positive",
		"kind: ModelPrices\nspec: { models: [{ match: a, input: 1, typo: 2 }] }\n": "field typo not found",
	} {
		if _, err := ParsePrices([]byte(doc)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", doc, err, want)
		}
	}
	if DocumentKind([]byte("kind: ModelPrices\n")) != "ModelPrices" {
		t.Error("kind")
	}
}
