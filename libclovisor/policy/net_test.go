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

func netProf(name, mode, udp, icmp string) string {
	return fmt.Sprintf(`
kind: AgentProfile
metadata: { name: %s }
spec:
  mode: %s
  egress: { default: deny }
  udp: { allow: %s }
  icmp: { allow: %s }
`, name, mode, udp, icmp)
}

func netStrings(g NetGrant) string {
	var parts []string
	for _, a := range g.UDP {
		parts = append(parts, a.String())
	}
	for _, p := range g.ICMP {
		parts = append(parts, "icmp "+p.String())
	}
	return strings.Join(parts, " ")
}

// A run gets the UDP and ICMP both its ceiling and every enforcing layer
// allow (milestone 4.7).
func TestNetGrant(t *testing.T) {
	game := netProf("game", "enforce", `["10.0.0.5:5000", "10.0.0.6:123", "[fd00::1]:5000"]`, `["10.0.0.0/8", "fd00::/64"]`)
	narrow := netProf("narrow", "enforce", `["10.0.0.5:5000"]`, `["10.1.2.3"]`)
	watch := netProf("watch", "audit", `[]`, `[]`)
	ceil := ceilingDoc("c", "{ any: true }", "[game, narrow, watch]", "game", "") +
		"  udp: { allow: [\"10.0.0.5:5000\", \"[fd00::1]:5000\"] }\n  icmp: { allow: [\"10.1.0.0/16\"] }\n"
	s := mustSet(t, game, narrow, watch, ceil)

	b, err := s.Resolve(Caller{UID: 1}, "game")
	if err != nil {
		t.Fatal(err)
	}
	// 10.0.0.6:123 is the profile's alone; the ceiling narrows ICMP to /16.
	if got := netStrings(b.Effective.Net()); got != "10.0.0.5:5000 [fd00::1]:5000 icmp 10.1.0.0/16" {
		t.Errorf("game: %s", got)
	}
	// A clamp narrows; an audit clamp does not.
	e := b.Effective.With(Layer{Profile: s.Profile("watch"), Source: "test"})
	if got := netStrings(e.Net()); got != "10.0.0.5:5000 [fd00::1]:5000 icmp 10.1.0.0/16" {
		t.Errorf("audit clamp: %s", got)
	}
	e = b.Effective.With(Layer{Profile: s.Profile("narrow"), Source: "test"})
	if got := netStrings(e.Net()); got != "10.0.0.5:5000 icmp 10.1.2.3/32" {
		t.Errorf("clamp: %s", got)
	}
	// A layer without the blocks, such as revoke, allows none.
	if g := b.Effective.With(Layer{Profile: RevokedProfile(), Source: "revoke"}).Net(); !g.Empty() {
		t.Errorf("revoke kept %s", netStrings(g))
	}
	// Nested: bounded by the parent.
	nb, _ := s.Resolve(Caller{UID: 1}, "narrow")
	if got := netStrings(Nested(nb.Effective, b.Effective).Net()); got != "10.0.0.5:5000 icmp 10.1.2.3/32" {
		t.Errorf("nested: %s", got)
	}
	// No enforcing layer: nothing granted (and nothing refused).
	wb, _ := s.Resolve(Caller{UID: 1}, "watch")
	if g := wb.Effective.Net(); !g.Empty() {
		t.Errorf("audit-only run: %s", netStrings(g))
	}
}

func TestNetGrantCeilingWithout(t *testing.T) {
	game := netProf("game", "enforce", `["10.0.0.5:5000"]`, `["10.0.0.0/8"]`)
	s := mustSet(t, game, ceilingDoc("c", "{ any: true }", "[game]", "game", ""))
	b, _ := s.Resolve(Caller{UID: 1}, "game")
	if g := b.Effective.Net(); !g.Empty() {
		t.Errorf("a ceiling without udp or icmp granted %s", netStrings(g))
	}
}

func TestNetErrors(t *testing.T) {
	for _, tc := range []struct{ udp, icmp, want string }{
		{`["10.0.0.5"]`, `[]`, "udp.allow[0]"},
		{`["0.0.0.0:5000"]`, `[]`, "name one address"},
		{`["10.0.0.5:53"]`, `[]`, "DNS always"},
		{`[]`, `["nonsense"]`, "icmp.allow[0]"},
	} {
		_, diags := newSet(t, netProf("p", "enforce", tc.udp, tc.icmp))
		if !strings.Contains(fmt.Sprint(diags), tc.want) {
			t.Errorf("%s %s: %v, want %q", tc.udp, tc.icmp, diags, tc.want)
		}
	}
	_, diags := newSet(t, netProf("p", "enforce", `[]`, `[]`),
		ceilingDoc("c", "{ any: true }", "[p]", "p", "")+"  udp: { allow: [\"bad\"] }\n")
	if !strings.Contains(fmt.Sprint(diags), "spec.udp.allow[0]") {
		t.Errorf("ceiling: %v", diags)
	}
}
