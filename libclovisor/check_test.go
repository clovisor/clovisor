// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"strings"
	"testing"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

func compileOne(t *testing.T, doc string) *policy.CompiledProfile {
	t.Helper()
	p, err := policy.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	c, diags := policy.Compile(policy.Options{Linux: true}, p)
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	return c.Profiles[0]
}

// A learned profile, checked against the runs it was learned from, has no
// violations: learn mode and the engine agree on what was seen.
func TestCheckLearnedProfileAgainstItsRuns(t *testing.T) {
	runs := learnRuns()
	var b strings.Builder
	if err := LearnProfile("learned", runs).WriteYAML(&b, t0); err != nil {
		t.Fatal(err)
	}
	rep := CheckRuns(compileOne(t, b.String()), runs)

	// The only violation is the literal-IP connect, whose rule learn mode
	// leaves disabled on purpose.
	if len(rep.Violations) != 1 || rep.Violations[0].What != "TCP 203.0.113.7:22" {
		t.Fatalf("violations: %+v", rep.Violations)
	}
	if len(rep.Allowed) == 0 {
		t.Fatal("nothing allowed")
	}
	kinds := map[string]int{}
	for _, f := range rep.NotGoverned {
		kinds[f.Decision]++
	}
	if kinds["loopback"] != 1 || kinds["UDP never reaches an explicit proxy"] != 1 || len(rep.NotGoverned) != 3 {
		t.Fatalf("not governed: %+v", rep.NotGoverned)
	}
}

func TestCheckTightenedProfile(t *testing.T) {
	rep := CheckRuns(compileOne(t, `
kind: AgentProfile
metadata: { name: tight }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - name: gh-read
        to: { fqdn: ["api.github.com"], ports: [443] }
        http: { methods: [GET] }
        action: allow
      - name: no-pypi
        to: { fqdn: ["pypi.org"] }
        action: deny
        message: "Use the internal mirror."
  exec:
    default: deny
    audit_only: true
    allow: [{ path: /usr/bin/git }]
`), learnRuns())

	var b strings.Builder
	rep.WriteText(&b)
	text := b.String()
	for _, want := range []string{
		"Profile tight@sha256:",
		"egress TCP pypi.org:443 (151.101.0.223)",
		"rule no-pypi: Use the internal mirror.",
		"egress TCP files.pythonhosted.org:443 (151.101.0.223)",
		"default: No rule in profile tight allows files.pythonhosted.org:443.",
		"exec   /usr/bin/python3",
		"not in exec.allow",
		"Depends on method or path, which audit data lacks",
		"TCP api.github.com:443 (140.82.112.6)",
		"first matching rule gh-read",
		"egress TCP api.github.com:80 (140.82.112.5)", // port 80 not allowed
		"[1/2 runs]",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if t.Failed() {
		t.Log(text)
	}
	for _, f := range rep.Allowed {
		if f.What == "/usr/bin/python3" {
			t.Error("python3 allowed")
		}
		if f.What == "/usr/bin/git" && f.Rule != "exec.allow" {
			t.Errorf("git allowed by %q, want exec.allow", f.Rule)
		}
	}
}
