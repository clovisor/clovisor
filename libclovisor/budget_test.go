// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// Spend survives a restart through the counter store, and is written to
// the owning run's metadata when it ends.
func TestBudgetSpendPersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "counters.json")
	s, _ := OpenCounterStore(path)
	l := NewBudgetLedger(nil, s)
	b := budgetOwner{BudgetCheck: policy.BudgetCheck{Layer: "p", Rule: "llm", Tokens: 100, Enforced: true}, owner: "parent"}
	st := l.charge([]budgetOwner{b}, policy.Usage{Input: 30, Output: 20}, 0.5, false, "child")
	if len(st) != 1 || st[0].Tokens != 50 || st[0].Run != "parent" || st[0].CostUSD != 0.5 {
		t.Fatalf("charge: %+v", st)
	}
	l.charge([]budgetOwner{b}, policy.Usage{Input: 1}, -1, true, "parent")
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s2, _ := OpenCounterStore(path)
	got := s2.Get("parent").Spend["p/llm"]
	if got == nil || got.Tokens != 51 || got.Requests != 2 || got.Unpriced != 1 || got.Estimated != 1 || got.LimitTokens != 100 {
		t.Fatalf("reloaded: %+v", got)
	}
	// Get returns a copy: changing it changes nothing stored.
	c := s2.Get("parent")
	c.Spend["p/llm"].Tokens = 0
	if s2.Get("parent").Spend["p/llm"].Tokens != 51 {
		t.Error("Get shares the stored spend")
	}

	api, lim, _, _ := limiterFixture(t, "")
	lim.store.Update("parent", func(rc *RunCounters) {
		rc.Spend = map[string]*BudgetSpend{"p/llm": {Layer: "p", Rule: "llm", Tokens: 7, CostUSD: 0.25, Requests: 1}}
	})
	lim.RunEnded("parent", 1)
	m, _ := api.reg.Get("parent")
	if want := []BudgetState{{Layer: "p", Rule: "llm", Tokens: 7, CostUSD: 0.25, Requests: 1}}; !reflect.DeepEqual(m.Budgets, want) {
		t.Errorf("metadata budgets: %+v", m.Budgets)
	}
}

func TestRunRecorderSpend(t *testing.T) {
	r := newTestRecorder(t)
	ev := func(ms int, d UsageData) AuditEvent {
		return AuditEvent{Type: EventUsage, Timestamp: at(ms), CgroupID: testRunCg, RunCgroupID: testRunCg, Data: d}
	}
	base := UsageData{Host: "api.example.com", Port: 443, Method: "POST", Path: "/v1/messages", Model: "gpt-5", Status: 200, Charged: true, Priced: true}
	with := func(f func(*UsageData)) UsageData { d := base; f(&d); return d }
	tl := feed(t, r,
		runEv(EventRunStart, 0, "/agents/run-abc"),
		ev(1, with(func(d *UsageData) {
			d.Usage, d.CostUSD = policy.Usage{Input: 10, Output: 5}, 0.01
			d.Budgets = []BudgetState{{Layer: "p", Rule: "llm", Run: "parent", Tokens: 15, CostUSD: 0.01}}
		})),
		ev(2, with(func(d *UsageData) { d.Usage, d.Estimated, d.CostUSD = policy.Usage{Input: 3}, true, 0.001 })),
		ev(3, with(func(d *UsageData) { d.Charged, d.Status = false, 529 })),
		ev(4, with(func(d *UsageData) { d.Charged, d.Refused = false, "no price for model" })),
		runEv(EventRunEnd, 5, "/agents/run-abc"),
	)
	want := []SpendUse{{Host: "api.example.com", Model: "gpt-5", Requests: 4, Usage: policy.Usage{Input: 13, Output: 5}, CostUSD: 0.011,
		Estimated: 1, Uncharged: 1, Refused: 1}}
	got := tl.Summary.Spend
	if len(got) != 1 || !near(got[0].CostUSD, 0.011) {
		t.Fatalf("spend %+v", got)
	}
	got[0].CostUSD = want[0].CostUSD
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("spend\n got %+v\nwant %+v", got, want)
	}
	var notes []string
	for _, e := range tl.Events {
		if e.Type == "usage" {
			notes = append(notes, e.Note)
		}
	}
	for i, w := range []string{"10 in, 5 out, $0.010000; budget p/llm of run parent now 15 tokens, $0.0100",
		"(estimated: no usage in the response)", "not charged: status 529", "refused: no price for model"} {
		if i >= len(notes) || !strings.Contains(notes[i], w) {
			t.Errorf("event %d: %q lacks %q", i, notes, w)
		}
	}
}

func TestLoadPolicyDirPrices(t *testing.T) {
	dir := writePolicy(t, map[string]string{"light.yaml": testProfile, "ceiling.yml": testCeiling, "prices.yaml": testPrices})
	set, err := LoadPolicyDir(dir, policy.Options{Linux: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := set.Prices.Price("gpt-5"); !ok || p.Output != 10 {
		t.Fatalf("prices: %+v %v", p, ok)
	}
	dir = writePolicy(t, map[string]string{"light.yaml": testProfile, "ceiling.yml": testCeiling, "a.yaml": testPrices, "b.yaml": testPrices})
	if _, err := LoadPolicyDir(dir, policy.Options{Linux: true}, false); err == nil || !strings.Contains(err.Error(), "a second ModelPrices document") {
		t.Errorf("two price lists: %v", err)
	}
}
