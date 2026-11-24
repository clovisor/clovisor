// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

// waitPending waits until q holds n requests and returns them.
func waitPending(t *testing.T, q *AskQueue, n int) []PendingAsk {
	t.Helper()
	all := func(PendingAsk) bool { return true }
	for i := 0; i < 200; i++ {
		if ps := q.List(all, false); len(ps) == n {
			return ps
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("queue never held %d: %+v", n, q.List(all, false))
	return nil
}

func TestAskQueue(t *testing.T) {
	q := NewAskQueue()
	ok := func(PendingAsk) error { return nil }
	p := PendingAsk{RunID: "r1", UID: 1000, Kind: "egress", What: "CONNECT pypi.org:443", Host: "pypi.org", Layer: "ap", Rule: "pypi"}
	ask := func(ctx context.Context, p PendingAsk, timeout time.Duration, allow bool) chan AskResult {
		ch := make(chan AskResult, 1)
		go func() { ch <- q.Ask(ctx, p, timeout, allow) }()
		return ch
	}

	// Approved.
	ch := ask(context.Background(), p, time.Minute, false)
	ps := waitPending(t, q, 1)
	if ps[0].State != AskPending || ps[0].OnTimeout != "deny" || ps[0].Expires.Sub(ps[0].Created) != time.Minute {
		t.Fatalf("pending: %+v", ps[0])
	}
	if _, err := q.Decide(ps[0].ID, true, false, "alice", func(PendingAsk) error { return errors.New("not yours") }); err == nil {
		t.Fatal("may ignored")
	}
	if got, err := q.Decide(ps[0].ID, true, false, "alice", ok); err != nil || got.State != AskApproved || got.By != "alice" {
		t.Fatalf("decide: %+v %v", got, err)
	}
	if r := <-ch; !r.Allowed || r.State != AskApproved || r.By != "alice" || r.ID != ps[0].ID {
		t.Fatalf("result: %+v", r)
	}

	// Denied, remembered: the next one is denied without asking.
	ch = ask(context.Background(), p, time.Minute, false)
	ps = waitPending(t, q, 1)
	q.Decide(ps[0].ID, false, true, "alice", ok)
	if r := <-ch; r.Allowed || r.State != AskDenied {
		t.Fatalf("denied: %+v", r)
	}
	if r := q.Ask(context.Background(), p, time.Minute, true); r.Allowed || r.State != AskRemembered || r.By != "alice" {
		t.Fatalf("remembered: %+v", r)
	}
	// Another host is asked about afresh.
	other := p
	other.Host = "files.pythonhosted.org"

	// Timeouts decide by on_timeout.
	if r := q.Ask(context.Background(), other, 20*time.Millisecond, true); !r.Allowed || r.State != AskTimedOut {
		t.Fatalf("timeout allow: %+v", r)
	}
	if r := q.Ask(context.Background(), other, 20*time.Millisecond, false); r.Allowed || r.State != AskTimedOut {
		t.Fatalf("timeout deny: %+v", r)
	}

	// The client goes away: abandoned. It can still be remembered.
	ctx, cancel := context.WithCancel(context.Background())
	ch = ask(ctx, other, time.Minute, false)
	ps = waitPending(t, q, 1)
	cancel()
	if r := <-ch; r.Allowed || r.State != AskAbandoned {
		t.Fatalf("abandoned: %+v", r)
	}
	if _, err := q.Decide(ps[0].ID, true, false, "alice", ok); err == nil || !strings.Contains(err.Error(), "use --remember") {
		t.Fatalf("decide abandoned: %v", err)
	}
	if got, err := q.Decide(ps[0].ID, true, true, "alice", ok); err != nil || !got.Remember {
		t.Fatalf("remember abandoned: %+v %v", got, err)
	}
	if r := q.Ask(context.Background(), other, time.Minute, false); !r.Allowed || r.State != AskRemembered {
		t.Fatalf("remembered approval: %+v", r)
	}
	if n := len(q.List(func(PendingAsk) bool { return true }, true)); n < 5 {
		t.Errorf("settled list: %d", n)
	}

	// Caps: past the per-run cap, not held.
	q.MaxHeldPerRun = 2
	var wg sync.WaitGroup
	results := make(chan AskResult, 3)
	third := p
	third.Host = "third.example"
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- q.Ask(context.Background(), third, time.Minute, false) }()
	}
	waitPending(t, q, 2)
	if r := q.Ask(context.Background(), third, time.Minute, false); r.State != AskRefused || !strings.Contains(r.Reason, "as many requests awaiting approval as it may (2)") {
		t.Fatalf("cap: %+v", r)
	}
	// The run ends: what it holds is abandoned, its remembered decisions
	// forgotten.
	q.ForgetRun("r1")
	wg.Wait()
	close(results)
	for r := range results {
		if r.State != AskAbandoned {
			t.Errorf("held at run end: %+v", r)
		}
	}
	if r := q.Ask(context.Background(), p, 10*time.Millisecond, false); r.State != AskTimedOut {
		t.Errorf("remembered after run end: %+v", r)
	}
}

const askXP = `kind: AgentProfile
metadata: { name: ax }
spec:
  mode: enforce
  ask: { timeout: 1m }
  egress:
    default: deny
    rules:
      - name: pypi
        to: { fqdn: ["pypi.org"], ports: [80, 443] }
        action: ask
        message: "A package install."
`

func TestExtProcAsk(t *testing.T) {
	xp, events, c := modelFixture(t, askXP)
	xp.Asks = NewAskQueue()
	var extended []time.Duration
	var mu sync.Mutex
	ctx := withExtender(context.Background(), func(d time.Duration) error {
		mu.Lock()
		extended = append(extended, d)
		mu.Unlock()
		return nil
	})
	attrs := map[string]interface{}{"source.address": c.src.String(), "destination.address": c.dst.String()}
	headers := func(method, authority, path string) chan *extprocv3.ProcessingResponse {
		ch := make(chan *extprocv3.ProcessingResponse, 1)
		go func() {
			req, h := reqWith(attrs, method, authority, path, nil)
			h.EndOfStream = true
			r, st := xp.onHeaders(ctx, req, h)
			st.done(xp)
			ch <- r
		}()
		return ch
	}
	ok := func(PendingAsk) error { return nil }

	// A tunnel is held, approved, and let through.
	ch := headers("CONNECT", "pypi.org:443", "")
	ps := waitPending(t, xp.Asks, 1)
	if ps[0].What != "CONNECT pypi.org:443" || ps[0].Message != "A package install." || ps[0].RunID != "testrun" || ps[0].Rule != "pypi" {
		t.Fatalf("pending: %+v", ps[0])
	}
	xp.Asks.Decide(ps[0].ID, true, false, "alice", ok)
	if code, msg := status(<-ch); code != 0 {
		t.Fatalf("approved: %d %s", code, msg)
	}
	mu.Lock()
	if len(extended) != 1 || extended[0] != time.Minute+askMargin {
		t.Errorf("timer extended: %v", extended)
	}
	mu.Unlock()

	// A plain request is held, denied, and narrated.
	ch = headers("GET", "pypi.org", "/simple/x/")
	ps = waitPending(t, xp.Asks, 1)
	if ps[0].What != "GET pypi.org/simple/x/" {
		t.Fatalf("pending: %+v", ps[0])
	}
	xp.Asks.Decide(ps[0].ID, false, false, "alice", ok)
	if code, msg := status(<-ch); code != 403 || msg != "A person declined GET pypi.org/simple/x/ (rule pypi of profile ax)." {
		t.Fatalf("denied: %d %q", code, msg)
	}

	// A CONNECT Envoy terminates is passed: its requests are asked about.
	tattrs := map[string]interface{}{"source.address": c.src.String(), "destination.address": c.dst.String(),
		"xds.route_name": TerminateRoutePrefix + "0"}
	req, h := reqWith(tattrs, "CONNECT", "pypi.org:443", "", nil)
	if r, _ := xp.onHeaders(ctx, req, h); r.GetImmediateResponse() != nil || len(xp.Asks.List(func(PendingAsk) bool { return true }, false)) != 0 {
		t.Fatalf("terminated CONNECT held: %v", r)
	}

	// Without a queue, ask rules refuse.
	xp.Asks = nil
	if code, msg := status(<-headers("GET", "pypi.org", "/")); code != 403 || !strings.Contains(msg, "this node agent takes none") {
		t.Fatalf("no queue: %d %s", code, msg)
	}

	var got []string
	for {
		select {
		case ev := <-events:
			if d, ok := ev.Data.(HTTPData); ok && d.Ask != nil {
				got = append(got, d.Method+":"+d.Decision+":"+d.Ask.State+":"+d.Ask.By+":"+d.Reason)
			}
			continue
		default:
		}
		break
	}
	want := "CONNECT:allow:approved:alice:ask: approved by alice,GET:deny:denied:alice:ask: denied by alice"
	if strings.Join(got, ",") != want {
		t.Errorf("records\n got %v\nwant %s", got, want)
	}
}

// Over the run API: the owner sees a run's held requests, but with
// credential identity only root may decide them, since the owner could be
// the agent itself.
func TestRunAPIAsks(t *testing.T) {
	dir := t.TempDir()
	api, err := NewRunAPIServer(filepath.Join(dir, "agent.sock"), nil, NewRunRegistry())
	if err != nil {
		t.Fatal(err)
	}
	api.Asks = NewAskQueue()
	go api.Serve()
	defer api.Close()
	rc, err := DialRunAPI(filepath.Join(dir, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	run, err := rc.Create([]string{"agent"}, dir, "")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan AskResult, 1)
	go func() {
		done <- api.Asks.Ask(context.Background(), PendingAsk{RunID: run.RunID, UID: api.ownerOf(run.RunID), Kind: "egress",
			What: "CONNECT pypi.org:443", Host: "pypi.org", Layer: "p", Rule: "r"}, time.Minute, false)
	}()
	waitPending(t, api.Asks, 1)
	other, _ := DialRunAPI(filepath.Join(dir, "agent.sock"))
	defer other.Close()
	r, err := other.Pending(false)
	if err != nil || len(r.Asks) != 1 || r.Asks[0].RunID != run.RunID {
		t.Fatalf("pending: %+v %v", r, err)
	}
	_, err = other.DecideAsk(r.Asks[0].ID, true, false)
	switch {
	case os.Getuid() == 0 && err != nil:
		t.Fatalf("root decide: %v", err)
	case os.Getuid() != 0 && (err == nil || !strings.Contains(err.Error(), "only root decides")):
		t.Fatalf("owner decide with credential identity: %v", err)
	}
	if os.Getuid() != 0 {
		api.Asks.ForgetRun(run.RunID)
	}
	<-done
}
