// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Sessions inside a run (milestone 7.3), with credential identity: the
// run's token mints them, each is decided by the run's policy and its own
// together, and each has a timeline of its own, nested in the run's.
func TestSessions(t *testing.T) {
	dir := t.TempDir()
	reg := NewRunRegistry()
	events := make(chan AuditEvent, 256)
	sock := filepath.Join(dir, "agent.sock")
	api, err := NewRunAPIServer(sock, nil, reg)
	if err != nil {
		t.Fatal(err)
	}
	api.ProxyURL, api.Events = "http://127.0.0.1:18000", events
	api.SetPolicy(grantSet(t, grantProfile, narrowProfile, grantCeiling))
	go api.Serve()
	defer api.Close()
	dial := func() *RunAPIClient {
		t.Helper()
		rc, err := DialRunAPI(sock)
		if err != nil {
			t.Fatal(err)
		}
		return rc
	}
	cred := func(r RunAPIResponse) (token, basic string) {
		t.Helper()
		u, err := url.Parse(r.Proxy)
		if err != nil || u.User == nil {
			t.Fatalf("proxy URL %q", r.Proxy)
		}
		token, _ = u.User.Password()
		return token, "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+token))
	}
	xp := NewExtProcServer(api, "", events)
	connect := func(basic, host string) (bool, string) {
		t.Helper()
		attrs := map[string]interface{}{"source.address": "127.0.0.1:40000", "destination.address": "127.0.0.1:18000"}
		req, hh := reqWith(attrs, "CONNECT", host+":443", "", map[string]string{"proxy-authorization": basic})
		resp, _ := xp.onHeaders(context.Background(), req, hh)
		ir := resp.GetImmediateResponse()
		if ir == nil {
			return true, ""
		}
		var body map[string]interface{}
		json.Unmarshal(ir.GetBody(), &body)
		msg, _ := body["message"].(string)
		return false, msg
	}

	runConn := dial()
	run, err := runConn.Create([]string{"server"}, dir, "g")
	if err != nil {
		t.Fatal(err)
	}
	runTok, runBasic := cred(run)

	// The token is the proof of being inside the run.
	if _, err := dial().Session("", ""); err == nil || !strings.Contains(err.Error(), "needs the token") {
		t.Fatalf("session without a token: %v", err)
	}
	if _, err := dial().Session("not-a-token", ""); err == nil || !strings.Contains(err.Error(), "names no live run") {
		t.Fatalf("session with a bad token: %v", err)
	}

	aConn := dial()
	a, err := aConn.Session(runTok, "narrow")
	if err != nil {
		t.Fatal(err)
	}
	if a.Identity != "session" || a.Parent != run.RunID || a.RunID == run.RunID {
		t.Fatalf("session: %+v", a)
	}
	aTok, aBasic := cred(a)
	if err := aConn.Attach(0); err == nil || !strings.Contains(err.Error(), "is a session") {
		t.Fatalf("attach to a session: %v", err)
	}

	// The session narrows the run; the run is unchanged.
	for _, c := range []struct {
		who, basic, host string
		want             bool
	}{
		{"run", runBasic, "github.com", true},
		{"run", runBasic, "pypi.org", true},
		{"session a", aBasic, "github.com", true},
		{"session a", aBasic, "pypi.org", false},
	} {
		if ok, msg := connect(c.basic, c.host); ok != c.want {
			t.Errorf("%s to %s: allowed=%v %q", c.who, c.host, ok, msg)
		}
	}

	// A session can only narrow: in a narrow run, asking for the wider
	// profile still leaves the run's limit.
	nConn := dial()
	nrun, err := nConn.Create([]string{"server"}, dir, "narrow")
	if err != nil {
		t.Fatal(err)
	}
	nTok, _ := cred(nrun)
	wConn := dial()
	w, err := wConn.Session(nTok, "g")
	if err != nil {
		t.Fatal(err)
	}
	_, wBasic := cred(w)
	if ok, _ := connect(wBasic, "pypi.org"); ok {
		t.Error("a session asking for more than its run was allowed it")
	}

	// A session nests in a session, by its token, and inherits its limit.
	bConn := dial()
	b, err := bConn.Session(aTok, "g")
	if err != nil {
		t.Fatal(err)
	}
	_, bBasic := cred(b)
	if b.Parent != a.RunID {
		t.Fatalf("nested session's parent %q, want %q", b.Parent, a.RunID)
	}
	if ok, _ := connect(bBasic, "pypi.org"); ok {
		t.Error("a session nested in a narrow session was allowed more")
	}

	// A session ends with its connection; the run goes on.
	bConn.Close()
	waitFor(t, func() bool { ok, _ := connect(bBasic, "github.com"); return !ok })
	if ok, _ := connect(runBasic, "github.com"); !ok {
		t.Fatal("run refused after its session ended")
	}
	// And with its run.
	if _, err := runConn.End(nil); err != nil {
		t.Fatal(err)
	}
	if ok, msg := connect(aBasic, "github.com"); ok || !strings.Contains(msg, "credential") {
		t.Fatalf("session of an ended run: allowed=%v %q", ok, msg)
	}
	aConn.Close()
	wConn.Close()
	nConn.End(nil)

	// Each session has a timeline of its own, marked as a session of its
	// parent, holding its own decisions.
	rec, err := NewCredentialRunRecorder(filepath.Join(dir, "runs"), reg)
	if err != nil {
		t.Fatal(err)
	}
	tls := map[string]*RunTimeline{}
	for len(events) > 0 {
		got, err := rec.Handle(<-events)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			tls[got.RunID] = got
		}
	}
	ta, tr := tls[a.RunID], tls[run.RunID]
	if ta == nil || tr == nil {
		t.Fatalf("timelines: %v", tls)
	}
	if !ta.Session || ta.Parent != run.RunID || tr.Session || !ta.Complete {
		t.Errorf("session timeline: session=%v parent=%q complete=%v; run session=%v", ta.Session, ta.Parent, ta.Complete, tr.Session)
	}
	if len(ta.Summary.Proxied) != 2 || len(tr.Summary.Proxied) != 2 {
		t.Errorf("proxied: session %+v, run %+v", ta.Summary.Proxied, tr.Summary.Proxied)
	}
	if !contains(tr.Children, a.RunID) {
		t.Errorf("run's children %v lack session %s", tr.Children, a.RunID)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in 2s")
}
