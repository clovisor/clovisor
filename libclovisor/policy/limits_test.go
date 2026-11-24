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

const limitsProfile = `kind: AgentProfile
metadata: { name: lp }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - name: search
        to: { fqdn: ["search.example.com"] }
        action: rate-limit
        rate: { requests: 2, per: 1m }
      - { name: api, to: { fqdn: ["api.example.com"] }, action: allow }
  limits:
    connections_per_min: 120
    egress_bytes: 100Mi
    duration: 30m
`

func TestParseBytes(t *testing.T) {
	for in, want := range map[string]uint64{"500000": 500000, "100Mi": 100 << 20, "2G": 2e9, "1Ki": 1024, "3K": 3000} {
		if got, err := ParseBytes(in); err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0", "-1", "1.5Gi", "10Q", "99999999999Ti"} {
		if _, err := ParseBytes(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestLimitsCompile(t *testing.T) {
	cp := compileContent(t, limitsProfile, "")
	if cp.Limits != (CompiledLimits{ConnectionsPerMin: 120, EgressBytes: 100 << 20, Duration: 30 * time.Minute}) {
		t.Fatalf("limits: %+v", cp.Limits)
	}
	rules := map[string]Placement{}
	for _, pl := range cp.Placements {
		rules[pl.Rule] = pl
	}
	for _, r := range []string{"limits/connections_per_min", "limits/egress_bytes", "limits/duration"} {
		if _, ok := rules[r]; !ok {
			t.Errorf("receipt lacks %s", r)
		}
	}
	if !strings.Contains(strings.Join(rules["search"].Notes, " "), "2 requests per 1m") {
		t.Errorf("search placement: %v", rules["search"].Notes)
	}

	errOf := func(doc string, opts Options) string {
		p, err := Parse([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		_, diags := Compile(opts, p)
		var b strings.Builder
		for _, d := range diags {
			b.WriteString(d.Error() + "\n")
		}
		return b.String()
	}
	linux := Options{Linux: true}
	for doc, want := range map[string]string{
		strings.Replace(limitsProfile, "duration: 30m", "duration: forever", 1):                                 `limits.duration: "forever" is not a duration`,
		strings.Replace(limitsProfile, "duration: 30m", "duration: 1ms", 1):                                     "limits.duration: must be between",
		strings.Replace(limitsProfile, "egress_bytes: 100Mi", "egress_bytes: lots", 1):                          "limits.egress_bytes:",
		strings.Replace(limitsProfile, "connections_per_min: 120", "connections_per_min: -1", 1):                "connections_per_min: must be between",
		strings.Replace(limitsProfile, "rate: { requests: 2, per: 1m }", "rate: { requests: 2, per: 1ms }", 1):  "rate.per must be between",
		strings.Replace(limitsProfile, "rate: { requests: 2, per: 1m }", "rate: { requests: 0, per: 1m }", 1):   "rate.requests must be between",
		strings.Replace(limitsProfile, "        rate: { requests: 2, per: 1m }\n", "", 1):                       "a rate-limit rule needs rate:",
		strings.Replace(limitsProfile, "action: allow }", "action: allow, rate: { requests: 1, per: 1m } }", 1): "rate: is only valid with action rate-limit",
	} {
		if got := errOf(doc, linux); !strings.Contains(got, want) {
			t.Errorf("want %q, got:\n%s", want, got)
		}
	}
	// Only the kernel sees every byte: egress_bytes needs the Linux agent.
	if got := errOf(limitsProfile, Options{}); !strings.Contains(got, "egress_bytes needs the Linux node agent") {
		t.Errorf("egress_bytes off Linux: %s", got)
	}
}

func TestRateHits(t *testing.T) {
	cp := compileContent(t, limitsProfile, "")
	eff := &Effective{Layers: []Layer{{Profile: cp}}}
	d := eff.Decide(Request{Host: "search.example.com", Port: 443, Phase: PhaseConnect})
	if !d.Allowed() || len(d.Rates) != 1 || d.Rates[0].Rule != "search" || d.Rates[0].Requests != 2 || d.Rates[0].Per != time.Minute ||
		!d.Rates[0].Enforced || d.Rates[0].Profile != cp {
		t.Fatalf("decision: %+v", d)
	}
	if d.Action != ActionAllow {
		t.Errorf("action %q: a rate-limited request is allowed while it has room", d.Action)
	}
	if !strings.Contains(d.Rates[0].RateMessage("search.example.com"), "limited to 2 per 1m0s by rule search of profile lp") {
		t.Errorf("message: %s", d.Rates[0].RateMessage("search.example.com"))
	}
	if d := eff.Decide(Request{Host: "api.example.com", Port: 443, Phase: PhaseConnect}); len(d.Rates) != 0 {
		t.Errorf("api rates: %+v", d.Rates)
	}
	// A layer on top adds its own allowance; both apply.
	other := compileContent(t, strings.Replace(limitsProfile, "name: lp", "name: lq", 1), "audit")
	both := eff.With(Layer{Profile: other})
	d = both.Decide(Request{Host: "search.example.com", Port: 443, Phase: PhaseConnect})
	if len(d.Rates) != 2 || d.Rates[1].Layer != "lq" || d.Rates[1].Enforced {
		t.Errorf("two layers: %+v", d.Rates)
	}
	if ls := both.Limits(); len(ls) != 2 || !ls[0].Enforced || ls[1].Enforced || ls[0].Duration != 30*time.Minute {
		t.Errorf("limits: %+v", ls)
	}
	if !both.Has(other) || eff.Has(other) {
		t.Error("Has")
	}
}
