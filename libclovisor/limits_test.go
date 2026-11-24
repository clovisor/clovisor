// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *fakeClock               { return &fakeClock{t: time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)} }
func compileProfile(t *testing.T, doc string) *policy.CompiledProfile {
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

func TestRateBuckets(t *testing.T) {
	clk := newClock()
	b := NewRateBuckets()
	b.now = clk.now
	for i := 0; i < 3; i++ {
		if ok, _ := b.take("r1", "k", 3, time.Minute); !ok {
			t.Fatalf("take %d refused", i)
		}
	}
	ok, wait := b.take("r1", "k", 3, time.Minute)
	if ok || wait != 20*time.Second {
		t.Fatalf("fourth: %v %v", ok, wait)
	}
	clk.add(20 * time.Second) // one token back
	if ok, _ := b.take("r1", "k", 3, time.Minute); !ok {
		t.Fatal("not refilled")
	}
	b.forget("r1")
	if ok, _ := b.take("r1", "k", 3, time.Minute); !ok || len(b.m) != 1 {
		t.Fatal("forget kept the bucket")
	}
}

func TestCounterStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "counters.json")
	s, err := OpenCounterStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Update("a", func(c *RunCounters) { c.EgressBytes = 10 })
	s.Update("b", func(c *RunCounters) { c.EgressBytes = 20 })
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s2, _ := OpenCounterStore(path)
	if s2.Get("a").EgressBytes != 10 || s2.Get("b").EgressBytes != 20 {
		t.Fatalf("reloaded: %+v", s2.runs)
	}
	s2.Keep(map[string]bool{"a": true})
	s2.Save()
	s3, _ := OpenCounterStore(path)
	if _, ok := s3.runs["b"]; ok || s3.Get("a").EgressBytes != 10 {
		t.Fatalf("keep: %+v", s3.runs)
	}
}

// fakeBytes is the kernel's byte count.
type fakeBytes struct {
	mu      sync.Mutex
	used    map[uint64]uint64
	limit   map[uint64]uint64
	dropped map[uint64]uint64
}

func (f *fakeBytes) SetRunBytes(cg, used, limit uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.used[cg] = max(f.used[cg], used)
	f.limit[cg] = limit
	return nil
}
func (f *fakeBytes) RunBytes(cg uint64) (uint64, uint64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.used[cg]
	return u, f.dropped[cg], ok
}
func (f *fakeBytes) ForgetRunBytes(cg uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.used, cg)
	delete(f.limit, cg)
}

// send is a packet from the first run, nested in the rest: as the kernel
// does, refused if it would take any of them past its limit.
func (f *fakeBytes) send(cgs []uint64, n uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	over := false
	for _, c := range cgs {
		if l := f.limit[c]; l != 0 && f.used[c]+n > l {
			f.dropped[c] += n
			over = true
		}
	}
	if over {
		return false
	}
	for _, c := range cgs {
		f.used[c] += n
	}
	return true
}

const limitedProfile = `kind: AgentProfile
metadata: { name: lim }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - { name: api, to: { fqdn: ["api.example.com"] }, action: allow }
      - name: search
        to: { fqdn: ["search.example.com"] }
        action: rate-limit
        rate: { requests: 2, per: 1m }
  limits:
    connections_per_min: 3
    egress_bytes: 1000
    duration: 10m
`

// limiterFixture is a run API with a run "parent" holding lim, and a run
// "child" nested in it holding lim and its own sub profile.
func limiterFixture(t *testing.T, sub string) (*RunAPIServer, *Limiter, *fakeBytes, *fakeClock) {
	t.Helper()
	lim := compileProfile(t, limitedProfile)
	parentEff := &policy.Effective{Layers: []policy.Layer{{Profile: lim}}}
	childEff := parentEff
	if sub != "" {
		childEff = policy.Nested(parentEff, &policy.Effective{Layers: []policy.Layer{{Profile: compileProfile(t, sub)}}})
	}
	clk := newClock()
	reg := NewRunRegistry()
	api := &RunAPIServer{reg: reg, active: map[string]bool{"parent": true, "child": true},
		bound: map[string]*boundRun{}, byCg: map[uint64]*boundRun{}, runByCg: map[uint64]string{}, runCg: map[string]uint64{"parent": 1, "child": 2},
		parentOf: map[string]string{"child": "parent"}, children: map[string][]string{"parent": {"child"}},
		tokens: map[string]string{}, tokOf: map[string]string{}}
	api.bound["parent"] = &boundRun{runID: "parent", cgroupID: 1, eff: parentEff, started: clk.now()}
	api.bound["child"] = &boundRun{runID: "child", cgroupID: 2, eff: childEff, started: clk.now().Add(time.Minute)}
	reg.Put(RunMeta{RunID: "parent"})
	reg.Put(RunMeta{RunID: "child", Parent: "parent"})
	fb := &fakeBytes{used: map[uint64]uint64{}, limit: map[uint64]uint64{}, dropped: map[uint64]uint64{}}
	store, _ := OpenCounterStore("")
	l := NewLimiter(api, fb, store, NewRateBuckets())
	l.now = clk.now
	l.RunStarted("parent", 1)
	l.RunStarted("child", 2)
	return api, l, fb, clk
}

func TestLimiterEgressBytes(t *testing.T) {
	const sub = `kind: AgentProfile
metadata: { name: sub }
spec:
  mode: enforce
  egress: { default: deny, rules: [ { name: api, to: { fqdn: ["api.example.com"] }, action: allow } ] }
  limits: { egress_bytes: 400 }
`
	api, l, fb, _ := limiterFixture(t, sub)
	// The kernel caps each run by the layers it holds itself: the child by
	// sub's 400, the parent by lim's 1000, which the child's bytes count to.
	if fb.limit[1] != 1000 || fb.limit[2] != 400 {
		t.Fatalf("kernel limits: %v", fb.limit)
	}
	fb.send([]uint64{2, 1}, 300) // the child sends; the kernel charges both
	fb.send([]uint64{1}, 500)    // the parent sends: 800
	l.check("parent")
	l.check("child")
	if p := api.effectiveOf("parent"); len(p.Layers) != 1 {
		t.Fatal("parent revoked under its limit")
	}
	if fb.send([]uint64{2, 1}, 300) { // the child would pass its 400
		t.Fatal("not refused")
	}
	l.check("child")
	if c := api.effectiveOf("child"); len(c.Layers) != 3 || c.Layers[2].Profile.Name != "limit-reached" {
		t.Fatalf("child not revoked: %+v", c.Layers)
	}
	if p := api.effectiveOf("parent"); len(p.Layers) != 1 {
		t.Fatal("the child's own limit revoked its parent")
	}
	if fb.send([]uint64{1}, 300) { // the parent would pass its 1000
		t.Fatal("parent not refused")
	}
	l.check("parent")
	if p := api.effectiveOf("parent"); len(p.Layers) != 2 {
		t.Fatal("parent not revoked over its limit")
	}
	d := api.effectiveOf("parent").Decide(policy.Request{Host: "api.example.com", Port: 443, Phase: policy.PhaseConnect})
	if d.Allowed() || !strings.Contains(d.Message, "more than its 1000 bytes egress limit (profile lim)") {
		t.Fatalf("revoked decision: %+v", d)
	}
	m, _ := api.reg.Get("parent")
	if len(m.Limits) != 1 || m.Limits[0].Limit != "egress_bytes" || m.Limits[0].Action != "revoked" {
		t.Fatalf("parent limits: %+v", m.Limits)
	}
	l.check("parent") // recorded once
	if m, _ := api.reg.Get("parent"); len(m.Limits) != 1 {
		t.Fatalf("recorded twice: %+v", m.Limits)
	}
	// What was sent, not what was refused: counted for a restart, and
	// reported at the end.
	if l.store.Get("parent").EgressBytes != 800 {
		t.Errorf("store: %+v", l.store.Get("parent"))
	}
	l.RunEnded("parent", 1)
	if m, _ := api.reg.Get("parent"); m.EgressBytes == nil || *m.EgressBytes != 800 {
		t.Errorf("egress bytes at end: %v", m.EgressBytes)
	}
	if _, ok := fb.used[1]; ok {
		t.Error("kernel entry not forgotten")
	}
}

func TestLimiterDuration(t *testing.T) {
	api, l, _, clk := limiterFixture(t, "")
	clk.add(9 * time.Minute)
	l.check("parent")
	if !api.active["parent"] {
		t.Fatal("ended early")
	}
	// The child inherited lim from its parent: its parent's clock, not its
	// own, which started a minute later, decides.
	clk.add(time.Minute)
	l.check("child")
	if !api.active["child"] {
		t.Fatal("the inherited duration ended the child on its own clock")
	}
	l.check("parent")
	alive := func() bool {
		api.mu.Lock()
		defer api.mu.Unlock()
		return api.active["parent"] || api.active["child"]
	}
	for deadline := time.Now().Add(2 * time.Second); alive() && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if alive() {
		t.Fatal("duration did not end the run and its nested run")
	}
	pm, _ := api.reg.Get("parent")
	cm, _ := api.reg.Get("child")
	if !strings.Contains(pm.EndReason, "duration limit of 10m0s (profile lim)") || !strings.Contains(cm.EndReason, "its parent run parent ended") {
		t.Fatalf("reasons: %q / %q", pm.EndReason, cm.EndReason)
	}
	if len(pm.Limits) != 1 || pm.Limits[0].Action != "ended" {
		t.Fatalf("limits: %+v", pm.Limits)
	}
}

func TestLimiterAudit(t *testing.T) {
	audit := strings.Replace(limitedProfile, "mode: enforce", "mode: audit", 1)
	lim := compileProfile(t, audit)
	clk := newClock()
	reg := NewRunRegistry()
	api := &RunAPIServer{reg: reg, active: map[string]bool{"r": true}, bound: map[string]*boundRun{}, byCg: map[uint64]*boundRun{},
		runByCg: map[uint64]string{}, runCg: map[string]uint64{"r": 1}, parentOf: map[string]string{}, children: map[string][]string{}}
	api.bound["r"] = &boundRun{runID: "r", cgroupID: 1, eff: &policy.Effective{Layers: []policy.Layer{{Profile: lim}}}, started: clk.now()}
	reg.Put(RunMeta{RunID: "r"})
	fb := &fakeBytes{used: map[uint64]uint64{}, limit: map[uint64]uint64{}, dropped: map[uint64]uint64{}}
	store, _ := OpenCounterStore("")
	l := NewLimiter(api, fb, store, nil)
	l.now = clk.now
	l.RunStarted("r", 1)
	if fb.limit[1] != 0 {
		t.Fatal("an audit layer set a kernel limit")
	}
	fb.send([]uint64{1}, 5000)
	clk.add(11 * time.Minute)
	l.check("r")
	m, _ := reg.Get("r")
	var got []string
	for _, h := range m.Limits {
		got = append(got, h.Limit+":"+h.Action)
	}
	if strings.Join(got, ",") != "duration:would end,egress_bytes:would revoke" || !api.active["r"] || len(api.effectiveOf("r").Layers) != 1 {
		t.Fatalf("audit: %v active=%v", got, api.active["r"])
	}
}

func TestExtProcRateLimits(t *testing.T) {
	xp, events, c := newTestExtProc(t, false)
	lim := compileProfile(t, limitedProfile)
	cg := ownCgroupID(t)
	b := &boundRun{runID: "testrun", cgroupID: cg, eff: &policy.Effective{Layers: []policy.Layer{{Profile: lim}}}}
	xp.api.bound["testrun"], xp.api.byCg[cg] = b, b
	xp.api.active["testrun"] = true
	clk := newClock()
	xp.Rates = NewRateBuckets()
	xp.Rates.now = clk.now
	connect := func(host string) (int, string, map[string]string) {
		req, h := headersReq(c, "CONNECT", host+":443", "")
		r, _ := xp.onHeaders(context.Background(), req, h)
		ir := r.GetImmediateResponse()
		if ir == nil {
			return 200, "", nil
		}
		var body struct {
			Message string `json:"message"`
		}
		json.Unmarshal(ir.GetBody(), &body)
		hdr := map[string]string{}
		for _, o := range ir.GetHeaders().GetSetHeaders() {
			hdr[o.GetHeader().GetKey()] = string(o.GetHeader().GetRawValue())
		}
		return int(ir.GetStatus().GetCode()), body.Message, hdr
	}
	// search: 2 a minute, by its rule.
	for i := 0; i < 2; i++ {
		if code, msg, _ := connect("search.example.com"); code != 200 {
			t.Fatalf("search %d: %d %s", i, code, msg)
		}
	}
	code, msg, hdr := connect("search.example.com")
	if code != 429 || !strings.Contains(msg, "limited to 2 per 1m0s by rule search of profile lim; retry in 30s") || hdr["retry-after"] != "30" {
		t.Fatalf("rate-limited: %d %q %v", code, msg, hdr)
	}
	// connections_per_min: 3, and the three above were connections too.
	code, msg, _ = connect("api.example.com")
	if code != 429 || !strings.Contains(msg, "may open 3 connections a minute (profile lim)") {
		t.Fatalf("connections: %d %q", code, msg)
	}
	clk.add(20 * time.Second) // one connection back
	if code, _, _ := connect("api.example.com"); code != 200 {
		t.Fatalf("after refill: %d", code)
	}
	var reasons []string
	for {
		select {
		case ev := <-events:
			if d, ok := ev.Data.(HTTPData); ok && d.Decision == "deny" {
				reasons = append(reasons, d.Reason+"/"+d.Rule)
			}
			continue
		default:
		}
		break
	}
	if strings.Join(reasons, ",") != "rate limit/search,connections_per_min/" {
		t.Errorf("recorded: %v", reasons)
	}
}

func TestOwner(t *testing.T) {
	a := compileProfile(t, limitedProfile)
	b := compileProfile(t, strings.Replace(limitedProfile, "name: lim", "name: other", 1))
	parent := &policy.Effective{Layers: []policy.Layer{{Profile: a}}}
	child := parent.With(policy.Layer{Profile: b})
	chain := []runLink{{runID: "p", eff: parent}, {runID: "c", eff: child}}
	if owner(chain, a) != "p" || owner(chain, b) != "c" {
		t.Errorf("owner: %s %s", owner(chain, a), owner(chain, b))
	}
	if ol := ownedLimits(chain); len(ol) != 1 || ol[0].Layer != "other" {
		t.Errorf("owned: %+v", ol)
	}
}
