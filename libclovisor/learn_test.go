// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"reflect"
	"strings"
	"testing"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

func learnRuns() []*RunTimeline {
	end := at(100)
	r1 := &RunTimeline{RunID: "r1", Command: []string{"agent", "task-1"}, StartedAt: at(0), EndedAt: &end, Complete: true,
		Summary: RunSummary{
			Binaries: []string{"/usr/bin/python3", "/usr/bin/git", "/usr/bin/sh"},
			DNSNames: []string{"api.github.com", "pypi.org", "nope.invalid", "files.pythonhosted.org"},
			Destinations: []Destination{
				{Proto: "UDP", IP: "127.0.0.53", Port: 53, Count: 6},
				{Proto: "TCP", IP: "140.82.112.6", Port: 443, Count: 3, Names: []string{"api.github.com"}},
				{Proto: "TCP", IP: "151.101.0.223", Port: 443, Count: 1, Names: []string{"files.pythonhosted.org", "pypi.org"}},
				{Proto: "UDP", IP: "151.101.0.223", Port: 443, Count: 1, Names: []string{"pypi.org"}},
				{Proto: "TCP", IP: "203.0.113.7", Port: 22, Count: 1},
				{Proto: "TCP", IP: "127.0.0.1", Port: 8080, Count: 2},
			},
		}}
	r2 := &RunTimeline{RunID: "r2", Command: []string{"agent", "task-2"}, StartedAt: at(200), EndedAt: &end, Complete: false,
		Summary: RunSummary{
			Binaries: []string{"/usr/bin/git", "/usr/local/bin/node22"},
			DNSNames: []string{"api.github.com"},
			Destinations: []Destination{
				{Proto: "TCP", IP: "140.82.112.5", Port: 443, Count: 2, Names: []string{"api.github.com"}},
				{Proto: "TCP", IP: "140.82.112.5", Port: 80, Count: 1, Names: []string{"api.github.com"}},
			},
		}}
	return []*RunTimeline{r1, r2}
}

func TestLearnProfile(t *testing.T) {
	d := LearnProfile("my-agent", learnRuns())
	var out strings.Builder
	if err := d.WriteYAML(&out, t0); err != nil {
		t.Fatal(err)
	}
	text := out.String()

	gotp, err := policy.Parse([]byte(text))
	if err != nil {
		t.Fatalf("draft is not valid profile YAML: %v\n%s", err, text)
	}
	got := *gotp
	if !reflect.DeepEqual(got, d.Profile) {
		t.Fatalf("rendered YAML does not round-trip:\n got %+v\nwant %+v\n%s", got, d.Profile, text)
	}

	if got.Kind != "AgentProfile" || got.Metadata.Name != "my-agent" || got.Spec.Mode != "audit" ||
		got.Spec.Egress.Default != "deny" || got.Spec.Exec.Default != "deny" || !got.Spec.Exec.RequireReadonlyOrigin {
		t.Fatalf("bad header: %+v", got)
	}

	// A draft must compile as it stands, so it can go straight to
	// shadowing (agentctl check) and audit-mode enforcement.
	if _, diags := policy.Compile(policy.Options{Linux: true}, gotp); len(diags) > 0 {
		t.Fatalf("draft does not compile: %v", diags)
	}

	wantRules := []policy.EgressRule{
		{Name: "api-github-com", To: policy.Destination{FQDN: []string{"api.github.com"}, Ports: []uint16{80, 443}}, Action: "allow"},
		{Name: "files-pythonhosted-org", To: policy.Destination{FQDN: []string{"files.pythonhosted.org"}, Ports: []uint16{443}}, Action: "allow"},
		{Name: "pypi-org", To: policy.Destination{FQDN: []string{"pypi.org"}, Ports: []uint16{443}}, Action: "allow"},
	}
	if !reflect.DeepEqual(got.Spec.Egress.Rules, wantRules) {
		t.Fatalf("rules %+v\nwant %+v", got.Spec.Egress.Rules, wantRules)
	}

	wantExec := []policy.ExecAllow{
		{Path: "/usr/bin/git"},
		{Path: "/usr/bin/python3", Note: "interpreter: allows arbitrary code; confinement comes from egress policy"},
		{Path: "/usr/bin/sh", Note: "interpreter: allows arbitrary code; confinement comes from egress policy"},
		{Path: "/usr/local/bin/node22", Note: "interpreter: allows arbitrary code; confinement comes from egress policy"},
	}
	if !reflect.DeepEqual(got.Spec.Exec.Allow, wantExec) {
		t.Fatalf("exec %+v\nwant %+v", got.Spec.Exec.Allow, wantExec)
	}

	// Things that must be reported for review but not allowed.
	for _, want := range []string{
		"#   r2  ", "[incomplete: events may be missing]",
		"# - name: \"ip-203-0-113-7-22\"", "cidr: [\"203.0.113.7/32\"], ports: [22]",
		"pypi.org:443 (1 connection, rule pypi-org)", // UDP/QUIC
		"TCP 127.0.0.1:8080 (2 connections)",         // loopback
		"DNS went to 127.0.0.53:53",
		"#   nope.invalid", // looked up, never connected
		"6 connections to 140.82.112.5, 140.82.112.6, 2/2 runs",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("draft lacks %q\n%s", want, text)
		}
	}
	if strings.Contains(text, "\n      - name: \"ip-") {
		t.Error("an IP rule is enabled; IP rules must be left disabled")
	}
}

func TestLearnProfileEmpty(t *testing.T) {
	end := at(1)
	d := LearnProfile("empty", []*RunTimeline{{RunID: "x", StartedAt: at(0), EndedAt: &end, Complete: true}})
	var out strings.Builder
	if err := d.WriteYAML(&out, t0); err != nil {
		t.Fatal(err)
	}
	got, err := policy.Parse([]byte(out.String()))
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if _, diags := policy.Compile(policy.Options{Linux: true}, got); len(diags) > 0 {
		t.Fatalf("empty draft does not compile: %v", diags)
	}
	if len(got.Spec.Egress.Rules) != 0 || len(got.Spec.Exec.Allow) != 0 {
		t.Fatalf("empty runs produced rules: %+v", got)
	}
}

// A run controls its command line, its binaries' paths and, through DNS,
// the names it connects to. None of it may change the drafted profile.
func TestLearnProfileIsNotInjectable(t *testing.T) {
	end := at(10)
	evil := "x\nspec:\n  egress:\n    default: allow\n# "
	runs := []*RunTimeline{{
		RunID: "r1\nkind: Evil", Command: []string{"sh", "-c", evil}, StartedAt: at(0), EndedAt: &end, Complete: true,
		Summary: RunSummary{
			Binaries: []string{"/tmp/a\n  - path: /bin/evil"},
			DNSNames: []string{"looked.up\n    default: allow"},
			Destinations: []Destination{
				{Proto: "TCP", IP: "192.0.2.1", Port: 443, Count: 1, Names: []string{"_srv.example.com"}},
				{Proto: "TCP", IP: "192.0.2.2", Port: 443, Count: 1, Names: []string{"bad\nname.example"}},
				{Proto: "UDP", IP: "192.0.2.3", Port: 443, Count: 1, Names: []string{"quic.example\n    default: allow"}},
				{Proto: "TCP", IP: "192.0.2.4", Port: 443, Count: 1, Names: []string{"good.example.com"}},
			},
		},
	}}
	var out strings.Builder
	if err := LearnProfile("p", runs).WriteYAML(&out, t0); err != nil {
		t.Fatal(err)
	}
	got, err := policy.Parse([]byte(out.String()))
	if err != nil {
		t.Fatalf("draft is not valid YAML: %v\n%s", err, out.String())
	}
	if got.Spec.Egress.Default != "deny" || got.Kind != "AgentProfile" {
		t.Fatalf("draft was altered by run data:\n%s", out.String())
	}
	if len(got.Spec.Egress.Rules) != 1 || got.Spec.Egress.Rules[0].To.FQDN[0] != "good.example.com" {
		t.Fatalf("rules: %+v", got.Spec.Egress.Rules)
	}
	if len(got.Spec.Exec.Allow) != 1 || got.Spec.Exec.Allow[0].Path != "/tmp/a\n  - path: /bin/evil" {
		t.Fatalf("exec: %+v", got.Spec.Exec.Allow)
	}
	if !strings.Contains(out.String(), `#   _srv.example.com (1 connection)`) {
		t.Errorf("invalid hostname not reported:\n%s", out.String())
	}
	// The exec path is not absolute-and-clean? It is absolute; the draft
	// must still compile so review can start from it.
	if _, diags := policy.Compile(policy.Options{Linux: true}, got); len(diags) > 0 {
		t.Fatalf("draft does not compile: %v", diags)
	}
}

func TestRuleNames(t *testing.T) {
	used := map[string]bool{}
	if a, b := uniqueRuleName(ruleName("A.B-c.com"), used), uniqueRuleName(ruleName("a.b.c.com"), used); a != "a-b-c-com" || b != "a-b-c-com-2" {
		t.Fatalf("got %q %q", a, b)
	}
	for in, want := range map[string]bool{"/usr/bin/python3.12": true, "/bin/bash": true, "/usr/bin/git": false, "/usr/bin/curl": false} {
		if isInterpreter(in) != want {
			t.Errorf("isInterpreter(%q) != %t", in, want)
		}
	}
}
