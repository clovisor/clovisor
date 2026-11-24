// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

func TestRunRecorderModels(t *testing.T) {
	r := newTestRecorder(t)
	ev := func(ms int, d ModelData) AuditEvent {
		return AuditEvent{Type: EventModel, Timestamp: at(ms), CgroupID: testRunCg, RunCgroupID: testRunCg, Data: d}
	}
	base := ModelData{Host: "api.example.com", Port: 443, Method: "POST", Path: "/v1/messages", Where: "body", Rule: "llm", Layer: "p"}
	with := func(f func(*ModelData)) ModelData { d := base; f(&d); return d }
	tl := feed(t, r,
		runEv(EventRunStart, 0, "/agents/run-abc"),
		ev(1, with(func(d *ModelData) { d.Model, d.Decision = "gpt-5", "allow" })),
		ev(2, with(func(d *ModelData) { d.Model, d.Decision = "gpt-5", "allow" })),
		ev(3, with(func(d *ModelData) { d.Model, d.Decision, d.Enforced = "gpt-4o", "deny", true })),
		ev(4, with(func(d *ModelData) { d.Decision, d.Enforced, d.Reason = "deny", true, "no model named" })),
		ev(5, with(func(d *ModelData) { d.Model, d.Decision, d.WouldDeny = "o3", "allow", []string{"a"} })),
		runEv(EventRunEnd, 6, "/agents/run-abc"),
	)
	u := func(model, reason string, n, denied, would int) ModelUse {
		return ModelUse{Host: "api.example.com", Port: 443, Method: "POST", Path: "/v1/messages", Model: model, Reason: reason,
			Layer: "p", Rule: "llm", Requests: n, Denied: denied, WouldDeny: would}
	}
	want := []ModelUse{u("", "no model named", 1, 1, 0), u("gpt-4o", "", 1, 1, 0), u("gpt-5", "", 2, 0, 0), u("o3", "", 1, 0, 1)}
	if !reflect.DeepEqual(tl.Summary.Models, want) {
		t.Fatalf("models\n got %+v\nwant %+v", tl.Summary.Models, want)
	}
	var notes []string
	for _, e := range tl.Events {
		if e.Type == "model" {
			notes = append(notes, e.Note)
		}
	}
	if len(notes) != 5 || notes[0] != `body: model "gpt-5"` || notes[3] != "body: no model" {
		t.Errorf("events: %q", notes)
	}
}

func modelRuns() []*RunTimeline {
	end := at(100)
	api := ProxiedDest{Host: "api.example.com", Port: 443, Connects: 1, Requests: 8, Paths: []PathUse{
		{Method: "POST", Path: "/v1/messages", Requests: 5, Denied: 1},
		{Method: "GET", Path: "/v1/models", Requests: 1},
		{Method: "POST", Path: "/v1/files", Requests: 1},
	}}
	models := []ModelUse{
		{Host: "api.example.com", Port: 443, Method: "POST", Path: "/v1/messages", Model: "claude-sonnet-5-5", Requests: 3},
		{Host: "api.example.com", Port: 443, Method: "POST", Path: "/v1/messages", Model: "claude-haiku-5-5", Requests: 1},
		{Host: "api.example.com", Port: 443, Method: "POST", Path: "/v1/messages", Model: "bad model", Requests: 1, Denied: 1},
		{Host: "api.example.com", Port: 443, Method: "POST", Path: "/v1/files", Reason: "its body is not a JSON object", Requests: 1},
	}
	r1 := &RunTimeline{RunID: "r1", Command: []string{"agent"}, StartedAt: at(0), EndedAt: &end, Complete: true,
		Summary: RunSummary{Proxied: []ProxiedDest{api}, Models: models}}
	return []*RunTimeline{r1}
}

func TestLearnModels(t *testing.T) {
	runs := modelRuns()
	d := LearnProfile("lm", runs)
	var b strings.Builder
	if err := d.WriteYAML(&b, t0); err != nil {
		t.Fatal(err)
	}
	text := b.String()
	got, err := policy.Parse([]byte(text))
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	if !reflect.DeepEqual(*got, d.Profile) {
		gj, _ := json.Marshal(got)
		wj, _ := json.Marshal(d.Profile)
		t.Fatalf("rendered YAML does not round-trip:\n got %s\nwant %s\n%s", gj, wj, text)
	}
	var rule *policy.EgressRule
	for i, r := range got.Spec.Egress.Rules {
		if r.HTTP != nil && len(r.HTTP.Methods) == 1 && r.HTTP.Methods[0] == "POST" {
			rule = &got.Spec.Egress.Rules[i]
		}
	}
	if rule == nil || rule.Model == nil || !reflect.DeepEqual(rule.Model.Allow, []string{"claude-haiku-5-5", "claude-sonnet-5-5"}) {
		t.Fatalf("POST rule: %+v\n%s", rule, text)
	}
	for _, s := range []string{
		"# Models named: claude-haiku-5-5 (1 request), claude-sonnet-5-5 (3 requests).",
		"# 1 request on these paths named no model (its body is not a JSON object); this rule refuses",
	} {
		if !strings.Contains(text, s) {
			t.Errorf("draft lacks %q:\n%s", s, text)
		}
	}
	if strings.Contains(text, "bad model") {
		t.Errorf("learned a refused model:\n%s", text)
	}
	for _, r := range got.Spec.Egress.Rules {
		if r.Model != nil && r.HTTP != nil && r.HTTP.Methods[0] == "GET" {
			t.Errorf("GET rule got a model list: %+v", r)
		}
	}

	// Replayed against its own runs: the models it learnt pass, the
	// refused one and the upload with no model would be refused.
	rep := CheckRuns(compileOne(t, text), runs)
	var viol, allowed []string
	for _, f := range rep.Violations {
		viol = append(viol, f.Kind+" "+f.What)
	}
	for _, f := range rep.Allowed {
		if f.Kind == "model" {
			allowed = append(allowed, f.What)
		}
	}
	wantViol := []string{
		`model POST api.example.com:443/v1/files (no model: its body is not a JSON object)`,
		`model POST api.example.com:443/v1/messages model "bad model"`,
	}
	if !reflect.DeepEqual(viol, wantViol) {
		t.Errorf("violations\n got %q\nwant %q", viol, wantViol)
	}
	if len(allowed) != 2 {
		t.Errorf("allowed models: %q", allowed)
	}
}

func TestCheckModelsUnrecorded(t *testing.T) {
	runs := modelRuns()
	runs[0].Summary.Models = nil // recorded under a profile with no model rule
	cp := compileOne(t, `kind: AgentProfile
metadata: { name: cm }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - name: llm
        to: { fqdn: ["api.example.com"] }
        model: { allow: ["claude-*"] }
        action: allow
`)
	rep := CheckRuns(cp, runs)
	var unver []string
	for _, f := range rep.Unverifiable {
		unver = append(unver, f.What)
	}
	want := []string{"POST api.example.com:443/v1/files (model not recorded)", "POST api.example.com:443/v1/messages (model not recorded)"}
	if !reflect.DeepEqual(unver, want) {
		t.Errorf("unverifiable\n got %q\nwant %q", unver, want)
	}
}
