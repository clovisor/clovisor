// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"net/netip"
	"strings"
	"testing"
)

// transparentRun looks like a run recorded under transparent mode, audit
// for the direct connects and enforce for the refusals.
func transparentRun() *RunTimeline {
	return &RunTimeline{RunID: "t1", Complete: true, StartedAt: t0, Command: []string{"agent"},
		Summary: RunSummary{
			DNSNames:   []string{"github.com", "evil.test"},
			DNSBlocked: []string{"blocked.test"},
			Destinations: []Destination{
				{Proto: "TCP", IP: "20.0.0.1", Port: 22, Count: 2, Names: []string{"github.com"}},
				{Proto: "UDP", IP: "8.8.8.8", Port: 443, Count: 3},
				{Proto: "UDP", IP: "162.159.200.123", Port: 123, Count: 1},
				{Proto: "UDP", IP: "127.0.0.53", Port: 53, Count: 4},
				{Proto: "TCP", IP: "127.0.0.1", Port: 3000, Count: 1},
			},
			UDPRefusedTo: []Destination{{Proto: "UDP", IP: "1.2.3.4", Port: 5000, Count: 9, Names: []string{"game.example"}}},
			Proxied: []ProxiedDest{{Host: "github.com", Port: 443, Requests: 5, Connects: 5, Tunnels: 5,
				Transparent: 5, AddrMismatches: 2},
				{Host: "20.0.0.9", Port: 22, Requests: 1, Connects: 1, Denied: 1, Transparent: 1}},
		},
		Events: []TimelineEvent{{Type: "dns", Query: "github.com", Answers: []DNSAnswer{{Name: "github.com", Type: "A", Value: "20.0.0.9"}}}}}
}

const transparentProfile = `kind: AgentProfile
metadata: { name: tp }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - { name: gh, to: { fqdn: ["github.com"], ports: [22, 443] }, action: allow }
`

func TestCheckTransparent(t *testing.T) {
	cp := compileOne(t, transparentProfile)
	runs := []*RunTimeline{transparentRun()}
	rep := CheckRunsWith(cp, runs, CheckOptions{Transparent: true,
		UDPAllow: []netip.AddrPort{netip.MustParseAddrPort("162.159.200.123:123")}})
	got := map[string]string{}
	for _, f := range rep.Violations {
		got[f.Kind+" "+f.What] = f.Message
	}
	for _, want := range []string{"dns evil.test", "dns blocked.test", "udp UDP 8.8.8.8:443", "udp UDP 1.2.3.4:5000 (game.example)"} {
		if _, ok := got[want]; !ok {
			t.Errorf("violations lack %q: %v", want, got)
		}
	}
	if !strings.Contains(got["udp UDP 8.8.8.8:443"], "QUIC") || !strings.HasPrefix(got["dns evil.test"], "NXDOMAIN") {
		t.Errorf("messages: %v", got)
	}
	if len(rep.Violations) != 5 { // plus the refused SSH tunnel by address
		t.Errorf("%d violations: %v", len(rep.Violations), got)
	}
	allowed := map[string]bool{}
	for _, f := range rep.Allowed {
		allowed[f.Kind+" "+f.What] = true
	}
	if !allowed["dns github.com"] || !allowed["udp UDP 162.159.200.123:123"] {
		t.Errorf("allowed: %v", allowed)
	}
	// SSH to github.com: allowed by name, but transparent mode sees the
	// address only.
	if len(rep.Unverifiable) != 1 || rep.Unverifiable[0].Kind != "by-address" || !strings.Contains(rep.Unverifiable[0].What, "github.com:22") {
		t.Errorf("unverifiable: %+v", rep.Unverifiable)
	}
	var b strings.Builder
	rep.WriteText(&b)
	if !strings.Contains(b.String(), "as transparent enforce would decide") || !strings.Contains(b.String(), "no cidr rule allows") {
		t.Errorf("report:\n%s", b.String())
	}

	// For an explicit proxy, the same runs: UDP and DNS are not governed,
	// and SSH is allowed by name.
	rep = CheckRuns(cp, runs)
	for _, f := range append(rep.Violations, rep.Unverifiable...) {
		if f.Kind == "dns" || f.Kind == "udp" || f.Kind == "by-address" {
			t.Errorf("explicit-proxy replay has %s %s", f.Kind, f.What)
		}
	}
}

func TestLearnTransparentNotes(t *testing.T) {
	var b strings.Builder
	if err := LearnProfile("tl", []*RunTimeline{transparentRun()}).WriteYAML(&b, t0); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{
		"Port 22: unless that traffic is TLS or HTTP",
		`cidr: ["20.0.0.1/32"], ports: [22]`,
		"2 connections sent to an address github.com does not resolve to",
		"UDP the node refused",
		"1.2.3.4:5000 game.example (9 attempts)",
		"refused by the node's resolver",
		"#   blocked.test",
		"Refused TCP to addresses the run had looked up by name",
		"#   20.0.0.9:22 (github.com) 1 time",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("draft lacks %q:\n%s", want, s)
		}
	}
	// Still a valid profile, and it allows nothing it was not shown.
	cp := compileOne(t, s)
	if len(cp.Rules) != 1 || cp.Rules[0].Name != "github-com" {
		t.Errorf("rules: %d", len(cp.Rules))
	}
}
