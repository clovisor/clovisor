// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Ask (milestone 5.5). A request an ask rule decides is held in the
// pending queue until a person approves or denies it over the run API
// (agentctl pending, approve, deny), or its timeout passes. A decision can
// be remembered for the rest of the run: later requests the same rule
// asks about, to the same host, are then decided without asking. Held
// requests are bounded node-wide and per run; past that, requests are
// refused rather than held.

// Ask queue defaults.
const (
	DefaultMaxHeldAsks       = 256
	DefaultMaxHeldAsksPerRun = 32
	// askKeep is how long a decided or abandoned request stays listed, so
	// that one a client gave up on can still be remembered.
	askKeep    = 10 * time.Minute
	maxDecided = 256
)

// Ask outcomes.
const (
	AskPending    = "pending"
	AskApproved   = "approved"
	AskDenied     = "denied"
	AskTimedOut   = "timed out"
	AskAbandoned  = "abandoned"  // the client went away first
	AskRemembered = "remembered" // decided by an earlier remembered decision
	AskRefused    = "not held"   // the queue was full
)

// PendingAsk is one request held for a decision, or recently decided.
type PendingAsk struct {
	ID      string    `json:"id"`
	RunID   string    `json:"run_id"`
	UID     int       `json:"uid"`  // the run's owner
	Kind    string    `json:"kind"` // egress or sampling
	What    string    `json:"what"` // "CONNECT pypi.org:443", "POST api.github.com/repos/a/b/issues"
	Host    string    `json:"host,omitempty"`
	Layer   string    `json:"layer"`
	Rule    string    `json:"rule,omitempty"`
	Message string    `json:"message,omitempty"` // the rule's message, for whoever decides
	Detail  string    `json:"detail,omitempty"`  // more of the request, cut short
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
	// OnTimeout is what happens when Expires passes: deny or allow.
	OnTimeout string     `json:"on_timeout"`
	State     string     `json:"state"`
	By        string     `json:"by,omitempty"` // who decided
	DecidedAt *time.Time `json:"decided_at,omitempty"`
	Remember  bool       `json:"remember,omitempty"`
}

// AskResult is the outcome of an ask.
type AskResult struct {
	ID      string
	Allowed bool
	State   string // approved, denied, timed out, abandoned, remembered, not held
	By      string
	Waited  time.Duration
	Reason  string // why it was not held
}

type askKey struct{ run, layer, rule, host string }

type askEntry struct {
	PendingAsk
	ch  chan AskResult
	key askKey
}

type askGrant struct {
	allow bool
	by    string
}

// AskQueue holds requests for decisions. Safe for concurrent use.
type AskQueue struct {
	MaxHeld       int
	MaxHeldPerRun int
	now           func() time.Time

	mu      sync.Mutex
	pending map[string]*askEntry
	perRun  map[string]int
	decided []PendingAsk
	grants  map[askKey]askGrant
	// OnChange, if set, is called when a request is held or decided.
	OnChange func(PendingAsk)
}

// NewAskQueue returns an empty queue.
func NewAskQueue() *AskQueue {
	return &AskQueue{now: time.Now, pending: map[string]*askEntry{}, perRun: map[string]int{}, grants: map[askKey]askGrant{}}
}

func newAskID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Ask holds p until it is decided, its timeout passes, or ctx ends (the
// client went away). allowOnTimeout says what a timeout decides.
func (q *AskQueue) Ask(ctx context.Context, p PendingAsk, timeout time.Duration, allowOnTimeout bool) AskResult {
	key := askKey{p.RunID, p.Layer, p.Rule, p.Host}
	start := q.now()
	q.mu.Lock()
	if g, ok := q.grants[key]; ok {
		q.mu.Unlock()
		return AskResult{Allowed: g.allow, State: AskRemembered, By: g.by}
	}
	maxHeld, maxRun := orDefault(q.MaxHeld, DefaultMaxHeldAsks), orDefault(q.MaxHeldPerRun, DefaultMaxHeldAsksPerRun)
	switch {
	case len(q.pending) >= maxHeld:
		q.mu.Unlock()
		return AskResult{State: AskRefused, Reason: fmt.Sprintf("the node holds as many requests for approval as it allows (%d)", maxHeld)}
	case q.perRun[p.RunID] >= maxRun:
		q.mu.Unlock()
		return AskResult{State: AskRefused, Reason: fmt.Sprintf("this run has as many requests awaiting approval as it may (%d)", maxRun)}
	}
	p.ID = newAskID()
	for q.pending[p.ID] != nil {
		p.ID = newAskID()
	}
	p.Created, p.Expires, p.State = start.UTC(), start.Add(timeout).UTC(), AskPending
	p.OnTimeout = "deny"
	if allowOnTimeout {
		p.OnTimeout = "allow"
	}
	e := &askEntry{PendingAsk: p, ch: make(chan AskResult, 1), key: key}
	q.pending[p.ID] = e
	q.perRun[p.RunID]++
	notify := q.OnChange
	q.mu.Unlock()
	if notify != nil {
		notify(p)
	}

	t := time.NewTimer(timeout)
	defer t.Stop()
	var r AskResult
	select {
	case r = <-e.ch:
	case <-t.C:
		r = AskResult{Allowed: allowOnTimeout, State: AskTimedOut}
		if !q.finish(e, r) {
			r = <-e.ch // decided as the timer fired
		}
	case <-ctx.Done():
		r = AskResult{State: AskAbandoned}
		if !q.finish(e, r) {
			r = <-e.ch
		}
	}
	r.ID, r.Waited = p.ID, q.now().Sub(start)
	return r
}

// finish settles e with r, unless it is already settled; it reports
// whether it settled it.
func (q *AskQueue) finish(e *askEntry, r AskResult) bool {
	q.mu.Lock()
	if q.pending[e.ID] != e {
		q.mu.Unlock()
		return false
	}
	delete(q.pending, e.ID)
	if q.perRun[e.RunID]--; q.perRun[e.RunID] <= 0 {
		delete(q.perRun, e.RunID)
	}
	now := q.now().UTC()
	e.State, e.By, e.DecidedAt = r.State, r.By, &now
	q.keep(e.PendingAsk)
	notify := q.OnChange
	q.mu.Unlock()
	e.ch <- r
	if notify != nil {
		notify(e.PendingAsk)
	}
	return true
}

// keep lists a settled request for a while. Called with q.mu held.
func (q *AskQueue) keep(p PendingAsk) {
	cut := q.now().Add(-askKeep)
	out := q.decided[:0]
	for _, d := range q.decided {
		if d.DecidedAt != nil && d.DecidedAt.After(cut) {
			out = append(out, d)
		}
	}
	q.decided = append(out, p)
	if len(q.decided) > maxDecided {
		q.decided = q.decided[len(q.decided)-maxDecided:]
	}
}

// Decide approves or denies a pending request, by who. remember makes the
// decision stand for later requests the same rule asks about, to the same
// host, for the rest of the run; a request already settled (abandoned, or
// timed out) can still be remembered. may vets the caller against the
// request.
func (q *AskQueue) Decide(id string, approve, remember bool, by string, may func(PendingAsk) error) (PendingAsk, error) {
	q.mu.Lock()
	e := q.pending[id]
	if e == nil {
		var settled *PendingAsk
		for i := range q.decided {
			if q.decided[i].ID == id {
				settled = &q.decided[i]
			}
		}
		if settled == nil {
			q.mu.Unlock()
			return PendingAsk{}, fmt.Errorf("no request %s is awaiting a decision", id)
		}
		p := *settled
		if err := may(p); err != nil {
			q.mu.Unlock()
			return PendingAsk{}, err
		}
		if !remember {
			q.mu.Unlock()
			return p, fmt.Errorf("request %s was already %s; use --remember to decide later requests like it", id, p.State)
		}
		q.grants[askKey{p.RunID, p.Layer, p.Rule, p.Host}] = askGrant{allow: approve, by: by}
		settled.Remember = true
		p.Remember = true
		q.mu.Unlock()
		return p, nil
	}
	if err := may(e.PendingAsk); err != nil {
		q.mu.Unlock()
		return PendingAsk{}, err
	}
	if remember {
		q.grants[e.key] = askGrant{allow: approve, by: by}
		e.Remember = true
	}
	q.mu.Unlock()
	state := AskDenied
	if approve {
		state = AskApproved
	}
	if !q.finish(e, AskResult{Allowed: approve, State: state, By: by}) {
		return PendingAsk{}, fmt.Errorf("request %s was settled meanwhile", id)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return e.PendingAsk, nil
}

// List returns pending requests, then recently settled ones, filtered by
// see.
func (q *AskQueue) List(see func(PendingAsk) bool, settled bool) []PendingAsk {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []PendingAsk
	for _, e := range q.pending {
		if see(e.PendingAsk) {
			out = append(out, e.PendingAsk)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	if settled {
		cut := q.now().Add(-askKeep)
		for _, d := range q.decided {
			if see(d) && d.DecidedAt != nil && d.DecidedAt.After(cut) {
				out = append(out, d)
			}
		}
	}
	return out
}

// ForgetRun drops a run's remembered decisions and settles what it still
// has held, as abandoned.
func (q *AskQueue) ForgetRun(runID string) {
	q.mu.Lock()
	for k := range q.grants {
		if k.run == runID {
			delete(q.grants, k)
		}
	}
	var held []*askEntry
	for _, e := range q.pending {
		if e.RunID == runID {
			held = append(held, e)
		}
	}
	q.mu.Unlock()
	for _, e := range held {
		q.finish(e, AskResult{State: AskAbandoned})
	}
}
