// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// Limits (milestone 5.2). A limit belongs to the run that holds the layer
// setting it. A nested run inherits its parent's layers, so its activity
// is charged to its parent's counts as well as its own: a sub-agent never
// gets a fresh allowance. owner finds that run.

// owner is the outermost run in chain holding the layer cp, which is
// whose allowance it is. A layer no run in the chain holds (cannot
// happen) is charged to the innermost.
func owner(chain []runLink, cp *policy.CompiledProfile) string {
	for _, l := range chain {
		if l.eff.Has(cp) {
			return l.runID
		}
	}
	return chain[len(chain)-1].runID
}

// ownedLimits are the layers of a run's policy that it holds itself, not
// through its parent.
func ownedLimits(chain []runLink) []policy.LayerLimits {
	self := chain[len(chain)-1]
	if self.eff == nil {
		return nil
	}
	var parent *policy.Effective
	if len(chain) > 1 {
		parent = chain[len(chain)-2].eff
	}
	var out []policy.LayerLimits
	for _, ll := range self.eff.Limits() {
		if !parent.Has(ll.Profile) {
			out = append(out, ll)
		}
	}
	return out
}

// RateBuckets are token buckets for connection and request rates, keyed by
// the run whose allowance it is.
type RateBuckets struct {
	mu  sync.Mutex
	m   map[string]*rateBucket
	now func() time.Time
}

type rateBucket struct {
	run    string
	tokens float64
	last   time.Time
}

// NewRateBuckets returns empty buckets.
func NewRateBuckets() *RateBuckets {
	return &RateBuckets{m: map[string]*rateBucket{}, now: time.Now}
}

// take spends one of n per per for key, owned by run. If there is none,
// it says how long until there is.
func (b *RateBuckets) take(run, key string, n int, per time.Duration) (bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	k := b.m[key]
	if k == nil {
		k = &rateBucket{run: run, tokens: float64(n), last: now}
		b.m[key] = k
	}
	rate := float64(n) / per.Seconds()
	k.tokens = math.Min(float64(n), k.tokens+now.Sub(k.last).Seconds()*rate)
	k.last = now
	if k.tokens >= 1 {
		k.tokens--
		return true, 0
	}
	return false, time.Duration((1 - k.tokens) / rate * float64(time.Second))
}

// forget drops the buckets of a run that ended.
func (b *RateBuckets) forget(run string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, v := range b.m {
		if v.run == run {
			delete(b.m, k)
		}
	}
}

// CounterStore keeps per-run counters across node agent restarts
// (milestone 5.2; budgets add to it in 5.4). Writes are eventually
// consistent: a restart loses at most the last few seconds.
type CounterStore struct {
	path  string
	mu    sync.Mutex
	runs  map[string]*RunCounters
	dirty bool
}

// RunCounters are what is counted for one run.
type RunCounters struct {
	EgressBytes uint64 `json:"egress_bytes,omitempty"`
	// Spend is what the run spent of the budgets it owns, by layer/rule
	// (milestone 5.4), nested runs included.
	Spend map[string]*BudgetSpend `json:"spend,omitempty"`
}

// clone copies c, its spend included.
func (c *RunCounters) clone() RunCounters {
	out := *c
	if c.Spend != nil {
		out.Spend = make(map[string]*BudgetSpend, len(c.Spend))
		for k, v := range c.Spend {
			sp := *v
			out.Spend[k] = &sp
		}
	}
	return out
}

// OpenCounterStore loads the store at path, or starts an empty one.
func OpenCounterStore(path string) (*CounterStore, error) {
	s := &CounterStore{path: path, runs: map[string]*RunCounters{}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		return s, nil
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(b, &s.runs); err != nil {
		log.Printf("limits: %s unreadable, starting counts afresh: %v", path, err)
		s.runs = map[string]*RunCounters{}
	}
	return s, nil
}

// Get returns a copy of a run's counters.
func (s *CounterStore) Get(run string) RunCounters {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.runs[run]; c != nil {
		return c.clone()
	}
	return RunCounters{}
}

// Update changes a run's counters.
func (s *CounterStore) Update(run string, f func(*RunCounters)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.runs[run]
	if c == nil {
		c = &RunCounters{}
		s.runs[run] = c
	}
	before := c.clone()
	f(c)
	if !reflect.DeepEqual(*c, before) {
		s.dirty = true
	}
}

// Delete forgets a run.
func (s *CounterStore) Delete(run string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[run]; ok {
		delete(s.runs, run)
		s.dirty = true
	}
}

// Keep forgets every run not in live: runs that ended while the node agent
// was down.
func (s *CounterStore) Keep(live map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for r := range s.runs {
		if !live[r] {
			delete(s.runs, r)
			s.dirty = true
		}
	}
}

// Save writes the store if it changed.
func (s *CounterStore) Save() error {
	s.mu.Lock()
	if !s.dirty || s.path == "" {
		s.mu.Unlock()
		return nil
	}
	b, err := json.Marshal(s.runs)
	s.dirty = false
	s.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// byteCounter is the kernel's egress byte count (EBPFReader).
type byteCounter interface {
	SetRunBytes(runCg, used, limit uint64) error
	RunBytes(runCg uint64) (sent, dropped uint64, ok bool)
	ForgetRunBytes(runCg uint64)
}

// Limiter enforces run limits that need the node agent: duration, and
// egress bytes, which the kernel counts and caps (milestone 5.2).
type Limiter struct {
	api     *RunAPIServer
	bytes   byteCounter // nil: no kernel (credential identity)
	store   *CounterStore
	buckets *RateBuckets
	// Ledger, if set, keeps budgets (milestone 5.4); a run's spend is
	// written to its metadata as it ends.
	Ledger *BudgetLedger
	now    func() time.Time

	mu    sync.Mutex
	state map[string]*limitState
}

type limitState struct {
	runCg       uint64
	kernelLimit uint64
	revoked     bool
	ended       bool
	noted       map[string]bool // limit hits already recorded
}

// NewLimiter returns a limiter for the run API's runs.
func NewLimiter(api *RunAPIServer, bytes byteCounter, store *CounterStore, buckets *RateBuckets) *Limiter {
	return &Limiter{api: api, bytes: bytes, store: store, buckets: buckets, now: time.Now, state: map[string]*limitState{}}
}

// RunStarted starts counting a run, before any process joins it, and
// applies its limits.
func (l *Limiter) RunStarted(runID string, runCg uint64) {
	l.mu.Lock()
	l.state[runID] = &limitState{runCg: runCg, noted: map[string]bool{}}
	l.mu.Unlock()
	if l.bytes != nil {
		if err := l.bytes.SetRunBytes(runCg, l.store.Get(runID).EgressBytes, 0); err != nil {
			log.Printf("limits: run %s: counting egress bytes: %v", runID, err)
		}
	}
	l.check(runID)
}

// RunEnded records what a run sent and forgets it.
func (l *Limiter) RunEnded(runID string, runCg uint64) {
	if l.bytes != nil {
		if n, _, ok := l.bytes.RunBytes(runCg); ok {
			l.api.reg.Update(runID, func(m *RunMeta) { m.EgressBytes = &n })
		}
		l.bytes.ForgetRunBytes(runCg)
	}
	if b := ownedBudgets(l.store.Get(runID)); len(b) > 0 {
		l.api.reg.Update(runID, func(m *RunMeta) { m.Budgets = b })
	}
	if l.Ledger != nil {
		l.Ledger.forget(runID)
	}
	l.store.Delete(runID)
	if l.buckets != nil {
		l.buckets.forget(runID)
	}
	l.mu.Lock()
	delete(l.state, runID)
	l.mu.Unlock()
}

// Resume picks up runs that were live across a node agent restart, and
// forgets counters of runs that ended meanwhile.
func (l *Limiter) Resume() {
	live := map[string]bool{}
	for _, r := range l.api.liveRuns() {
		live[r] = true
	}
	l.store.Keep(live)
}

// Run checks every live run each interval until done closes.
func (l *Limiter) Run(interval time.Duration, done <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	saved := time.Now()
	for {
		select {
		case <-done:
			l.store.Save()
			return
		case <-t.C:
		}
		for _, r := range l.api.liveRuns() {
			l.check(r)
		}
		if time.Since(saved) >= 5*time.Second {
			if err := l.store.Save(); err != nil {
				log.Printf("limits: saving counters: %v", err)
			}
			saved = time.Now()
		}
	}
}

func (l *Limiter) hit(runID string, st *limitState, h LimitHit) {
	key := h.Limit + "/" + h.Layer + "/" + h.Action
	l.mu.Lock()
	seen := st.noted[key]
	st.noted[key] = true
	l.mu.Unlock()
	if seen {
		return
	}
	l.api.reg.Update(runID, func(m *RunMeta) { m.Limits = append(append([]LimitHit{}, m.Limits...), h) })
}

// check applies a run's own limits: those of the layers it holds itself.
// Its parent's are checked on its parent, whose counts include it.
func (l *Limiter) check(runID string) {
	l.mu.Lock()
	st := l.state[runID]
	l.mu.Unlock()
	if st == nil {
		return
	}
	chain := l.api.chain(runID)
	if len(chain) == 0 {
		return
	}
	self := chain[len(chain)-1]
	now := l.now()
	var used, dropped uint64
	var counted bool
	if l.bytes != nil {
		used, dropped, counted = l.bytes.RunBytes(st.runCg)
		if counted {
			l.store.Update(runID, func(c *RunCounters) { c.EgressBytes = used })
		}
	}
	owned := ownedLimits(chain)
	// The kernel enforces the smallest of the run's own enforced limits,
	// refusing any packet that would pass it.
	var kernelLimit uint64
	for _, ll := range owned {
		if ll.Enforced && ll.EgressBytes > 0 && (kernelLimit == 0 || ll.EgressBytes < kernelLimit) {
			kernelLimit = ll.EgressBytes
		}
	}
	for _, ll := range owned {
		if ll.Duration > 0 && !self.started.IsZero() && now.Sub(self.started) >= ll.Duration {
			h := LimitHit{At: now.UTC(), Limit: "duration", Layer: ll.Layer, Value: ll.Duration.String()}
			if ll.Enforced {
				l.mu.Lock()
				ended := st.ended
				st.ended = true
				l.mu.Unlock()
				if !ended {
					h.Action = "ended"
					l.hit(runID, st, h)
					go l.api.EndRunFor(runID, fmt.Sprintf("it reached its duration limit of %s (profile %s)", ll.Duration, ll.Layer))
				}
				return
			}
			h.Action = "would end"
			l.hit(runID, st, h)
		}
		if ll.EgressBytes > 0 {
			// Reached: for the enforced limit, when the kernel refused
			// a packet; for an audit layer's, when what was sent passed it.
			reached := used > ll.EgressBytes
			if ll.Enforced {
				reached = ll.EgressBytes == kernelLimit && (dropped > 0 || used >= ll.EgressBytes)
			}
			if counted && reached {
				h := LimitHit{At: now.UTC(), Limit: "egress_bytes", Layer: ll.Layer, Value: bytesString(ll.EgressBytes)}
				if !ll.Enforced {
					h.Action = "would revoke"
					l.hit(runID, st, h)
				} else {
					l.revoke(runID, st, h, fmt.Sprintf("This run has sent more than its %s egress limit (profile %s); its egress is revoked.",
						bytesString(ll.EgressBytes), ll.Layer))
				}
			}
		}
	}
	if l.bytes != nil && kernelLimit != st.kernelLimit {
		if err := l.bytes.SetRunBytes(st.runCg, used, kernelLimit); err != nil {
			log.Printf("limits: run %s: egress byte limit: %v", runID, err)
		} else {
			st.kernelLimit = kernelLimit
		}
	}
}

// revoke refuses all of a run's egress, with a narration, once. The
// kernel has already started dropping its packets.
func (l *Limiter) revoke(runID string, st *limitState, h LimitHit, msg string) {
	l.mu.Lock()
	done := st.revoked
	st.revoked = true
	l.mu.Unlock()
	if done {
		return
	}
	h.Action = "revoked"
	l.hit(runID, st, h)
	layer := policy.Layer{Profile: policy.LimitedProfile(msg), Source: "node agent: " + h.Limit + " limit"}
	if _, err := l.api.applyLayer(runID, layer, nil); err != nil {
		log.Printf("limits: run %s: revoking egress: %v", runID, err)
	}
}

// retryIn rounds a wait up to whole seconds, as Retry-After counts them.
func retryIn(d time.Duration) time.Duration {
	return time.Duration(math.Ceil(d.Seconds())) * time.Second
}

func bytesString(n uint64) string {
	for _, u := range []struct {
		s string
		m uint64
	}{{"Ti", 1 << 40}, {"Gi", 1 << 30}, {"Mi", 1 << 20}, {"Ki", 1 << 10}} {
		if n >= u.m && n%u.m == 0 {
			return strconv.FormatUint(n/u.m, 10) + u.s
		}
	}
	return strconv.FormatUint(n, 10) + " bytes"
}

// checkRates applies connection limits and rate-limit rules to a request
// the policy allowed (milestone 5.2), charging the allowance of the run
// that holds each layer. connection: it opens a connection (a CONNECT,
// or a plain-HTTP request from the run itself), so connections_per_min
// counts it. request: it is a request rate-limit rules count; a CONNECT
// Envoy terminates is not, the requests inside it are.
func (s *ExtProcServer) checkRates(d *HTTPData, ed policy.EffectiveDecision, eff *policy.Effective, runID string, connection, request bool) (bool, time.Duration) {
	if s.Rates == nil || eff == nil {
		return true, 0
	}
	var chain []runLink
	who := func(cp *policy.CompiledProfile) string {
		if chain == nil {
			if chain = s.api.chain(runID); len(chain) == 0 {
				chain = []runLink{{runID: runID, eff: eff}}
			}
		}
		return owner(chain, cp)
	}
	target := d.Host
	refuse := func(layer, rule, reason, msg string, wait time.Duration) (bool, time.Duration) {
		d.Decision, d.Enforced, d.Layer, d.Rule, d.Reason, d.Message = policy.ActionDeny, true, layer, rule, reason, msg
		return false, wait
	}
	would := func(layer, reason string) {
		d.WouldDeny = append(d.WouldDeny, layer)
		if d.Reason == "" {
			d.Reason = "audit: " + reason
		}
	}
	if connection {
		for _, ll := range eff.Limits() {
			if ll.ConnectionsPerMin == 0 {
				continue
			}
			o := who(ll.Profile)
			ok, wait := s.Rates.take(o, "conn/"+o+"/"+ll.Layer, ll.ConnectionsPerMin, time.Minute)
			if ok {
				continue
			}
			if !ll.Enforced {
				would(ll.Layer, "connections_per_min")
				continue
			}
			msg := fmt.Sprintf("This run may open %d connections a minute (profile %s), and has; retry in %s.",
				ll.ConnectionsPerMin, ll.Layer, retryIn(wait))
			if o != runID {
				msg = fmt.Sprintf("Run %s and the runs nested in it may open %d connections a minute (profile %s), and have; retry in %s.",
					o, ll.ConnectionsPerMin, ll.Layer, retryIn(wait))
			}
			return refuse(ll.Layer, "", "connections_per_min", msg, wait)
		}
	}
	if request {
		for _, h := range ed.Rates {
			o := who(h.Profile)
			ok, wait := s.Rates.take(o, "rate/"+o+"/"+h.Layer+"/"+h.Rule, h.Requests, h.Per)
			if ok {
				continue
			}
			if !h.Enforced {
				would(h.Layer, "rate limit "+h.Rule)
				continue
			}
			msg := h.Message
			if msg == "" {
				msg = strings.TrimSuffix(h.RateMessage(target), "; retry later.") + fmt.Sprintf("; retry in %s.", retryIn(wait))
			}
			return refuse(h.Layer, h.Rule, "rate limit", msg, wait)
		}
	}
	return true, 0
}
