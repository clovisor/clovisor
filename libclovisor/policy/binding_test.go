// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"fmt"
	"strings"
	"testing"
)

func prof(name, mode, rules string) string {
	return fmt.Sprintf(`
kind: AgentProfile
metadata: { name: %s }
spec:
  mode: %s
  egress:
    default: deny
    rules:
%s`, name, mode, rules)
}

var (
	research = prof("research", "enforce", `
      - { name: gh, to: { fqdn: ["github.com", "api.github.com"] }, action: allow }
      - { name: pypi, to: { fqdn: ["pypi.org"] }, action: allow }
      - { name: tel, to: { fqdn: ["telemetry.internal"] }, action: tag-and-log }
`)
	light = prof("light", "enforce", `
      - { name: gh, to: { fqdn: ["github.com"] }, action: allow }
`)
	// A baseline clamped into every grant: no pypi, enforced.
	baseline = prof("baseline", "enforce", `
      - { name: no-pypi, to: { fqdn: ["pypi.org"] }, action: deny, message: "Use the internal mirror." }
      - { name: rest, to: { fqdn: ["*"] }, action: allow }
`)
	// An audit-mode clamp only records would-deny.
	shadow = prof("shadow", "audit", `
      - { name: gh-only, to: { fqdn: ["github.com"] }, action: allow }
`)
)

func ceilingDoc(name, applies, allow, def, clamp string) string {
	s := fmt.Sprintf("kind: ProfileCeiling\nmetadata: { name: %s }\nspec:\n  appliesTo: %s\n  allow: %s\n", name, applies, allow)
	if def != "" {
		s += "  default: " + def + "\n"
	}
	if clamp != "" {
		s += "  clamp: " + clamp + "\n"
	}
	return s
}

func lookup(names map[string]int) func(string) (int, error) {
	return func(n string) (int, error) {
		if id, ok := names[n]; ok {
			return id, nil
		}
		return 0, fmt.Errorf("unknown %q", n)
	}
}

func newSet(t *testing.T, docs ...string) (*Set, []Diagnostic) {
	t.Helper()
	var ps []*AgentProfile
	var cs []*ProfileCeiling
	for _, d := range docs {
		p, c, err := ParseDocument([]byte(d))
		if err != nil {
			t.Fatalf("%v\n%s", err, d)
		}
		if p != nil {
			ps = append(ps, p)
		} else {
			cs = append(cs, c)
		}
	}
	return NewSet(Options{Linux: true}, ps, cs,
		lookup(map[string]int{"alice": 1001, "bob": 1002}), lookup(map[string]int{"agents": 500, "ops": 600}))
}

func mustSet(t *testing.T, docs ...string) *Set {
	t.Helper()
	s, diags := newSet(t, docs...)
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	return s
}

func TestResolve(t *testing.T) {
	s := mustSet(t, research, light, baseline, shadow,
		ceilingDoc("alice", "{ user: alice }", "[research, light]", "light", ""),
		ceilingDoc("agents", "{ group: agents }", "[light]", "light", "baseline"),
		ceilingDoc("everyone", "{ any: true }", "[]", "light", "shadow"),
	)
	alice := Caller{UID: 1001, GIDs: []int{1001, 500}}
	bob := Caller{UID: 1002, GIDs: []int{1002, 500}}
	carol := Caller{UID: 1003, GIDs: []int{1003}}

	cases := []struct {
		caller          Caller
		req             string
		granted, ceil   string
		layers          int
		reasonSubstring string
	}{
		// uid beats group: alice is in "agents" but her own ceiling wins.
		{alice, "research", "research", "alice", 1, "requested"},
		{alice, "", "light", "alice", 1, "default of ceiling alice"},
		// A request the ceiling does not allow falls back to the default,
		// and says so.
		{bob, "research", "light", "agents", 2, `requested "research" is not allowed by ceiling agents`},
		{carol, "", "light", "everyone", 2, "default"},
	}
	for _, tc := range cases {
		b, err := s.Resolve(tc.caller, tc.req)
		if err != nil {
			t.Errorf("uid %d %q: %v", tc.caller.UID, tc.req, err)
			continue
		}
		if b.Granted().Name != tc.granted || b.Ceiling != tc.ceil || len(b.Effective.Layers) != tc.layers ||
			!strings.Contains(b.Reason, tc.reasonSubstring) {
			t.Errorf("uid %d %q: granted %s via %s, %d layers, reason %q", tc.caller.UID, tc.req,
				b.Granted().Name, b.Ceiling, len(b.Effective.Layers), b.Reason)
		}
	}

	// No ceiling at all: unprofiled is allowed, asking for a profile is not.
	only := mustSet(t, light, ceilingDoc("alice", "{ uid: 1001 }", "[light]", "", ""))
	if _, err := only.Resolve(carol, ""); err != ErrNoCeiling {
		t.Errorf("uncovered caller without a request: %v", err)
	}
	if _, err := only.Resolve(carol, "light"); err == nil {
		t.Error("uncovered caller got a profile")
	}
	// No default and nothing requested.
	if _, err := only.Resolve(alice, ""); err == nil || !strings.Contains(err.Error(), "has no default") {
		t.Errorf("no default: %v", err)
	}
	// Two group ceilings covering the same caller are ambiguous.
	amb := mustSet(t, light,
		ceilingDoc("a", "{ group: agents }", "[light]", "light", ""),
		ceilingDoc("o", "{ group: ops }", "[light]", "light", ""))
	if _, err := amb.Resolve(Caller{UID: 7, GIDs: []int{500, 600}}, ""); err == nil || !strings.Contains(err.Error(), "make one of them more specific") {
		t.Errorf("ambiguous ceilings: %v", err)
	}
}

func TestEffectiveIntersection(t *testing.T) {
	s := mustSet(t, research, baseline, shadow,
		ceilingDoc("c", "{ any: true }", "[research]", "research", "baseline"))
	b, err := s.Resolve(Caller{UID: 1}, "research")
	if err != nil {
		t.Fatal(err)
	}
	e := b.Effective

	// Allowed by research, denied by the enforced baseline clamp.
	d := e.Decide(Request{Host: "pypi.org", Port: 443})
	if d.Allowed() || !d.Enforced || d.Layer != "baseline" || d.Message != "Use the internal mirror." {
		t.Errorf("clamp deny: %+v", d)
	}
	// Allowed by both.
	if d := e.Decide(Request{Host: "api.github.com", Port: 443}); !d.Allowed() || d.Rule != "gh" {
		t.Errorf("both allow: %+v", d)
	}
	// Allowed by the clamp's wildcard, but not by the grant: still denied.
	if d := e.Decide(Request{Host: "example.com", Port: 443}); d.Allowed() || d.Layer != "research" {
		t.Errorf("grant deny: %+v", d)
	}
	// tag-and-log survives intersection.
	if d := e.Decide(Request{Host: "telemetry.internal", Port: 443}); d.Action != ActionTagAndLog {
		t.Errorf("tag-and-log lost: %+v", d)
	}

	// An audit-mode clamp records would-deny but blocks nothing.
	e2 := e.With(Layer{Profile: s.Profile("shadow"), Source: "test"})
	d = e2.Decide(Request{Host: "api.github.com", Port: 443})
	if !d.Allowed() || len(d.WouldDeny) != 1 || d.WouldDeny[0] != "shadow" {
		t.Errorf("audit clamp: %+v", d)
	}
	if len(e.Layers) != 2 {
		t.Error("With mutated the original")
	}

	// Revoke denies everything, with its own narration.
	e3 := e.With(Layer{Profile: RevokedProfile(), Source: "revoke"})
	d = e3.Decide(Request{Host: "api.github.com", Port: 443})
	if d.Allowed() || d.Layer != "revoked" || d.Message != "Egress for this run has been revoked." {
		t.Errorf("revoke: %+v", d)
	}
}

func TestCeilingErrors(t *testing.T) {
	_, diags := newSet(t, light,
		ceilingDoc("missing", "{ uid: 5 }", "[nope]", "gone", "absent"),
		ceilingDoc("two", "{ uid: 6, any: true }", "[light]", "", ""),
		ceilingDoc("k8s", "{ namespace: agents }", "[light]", "", ""),
		ceilingDoc("who", "{ user: mallory }", "[light]", "", ""),
		ceilingDoc("dup", "{ uid: 5 }", "[light]", "", ""),
		ceilingDoc("empty", "{ uid: 9 }", "[]", "", ""),
	)
	var all []string
	for _, d := range diags {
		all = append(all, d.Error())
	}
	text := strings.Join(all, "\n")
	for _, want := range []string{
		`ceiling missing: spec.allow: no profile named "nope"`,
		`ceiling missing: spec.default: no profile named "gone"`,
		`ceiling missing: spec.clamp: no profile named "absent"`,
		"ceiling two: spec.appliesTo: needs exactly one of",
		"ceiling k8s: spec.appliesTo: namespace and serviceAccount need Kubernetes identity",
		`ceiling who: spec.appliesTo.user: unknown "mallory"`,
		"ceiling dup: spec.appliesTo: selects the same callers as ceiling missing",
		"ceiling empty: spec: grants nothing",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q", want)
		}
	}
	if t.Failed() {
		t.Log(text)
	}
	if _, _, err := ParseDocument([]byte("kind: Pod\n")); err == nil {
		t.Error("unknown kind accepted")
	}
	if _, _, err := ParseDocument([]byte("kind: ProfileCeiling\nspec: { appliesto: {} }\n")); err == nil {
		t.Error("misspelt ceiling field accepted")
	}
}
