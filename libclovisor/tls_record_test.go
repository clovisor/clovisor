// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

func tlsEv(ms int, r TLSRequest) AuditEvent {
	return AuditEvent{Type: EventTLS, Timestamp: at(ms), CgroupID: testRunCg, RunCgroupID: testRunCg, PID: 10,
		Data: TLSEventData{TLSRequest: r, Lib: "libssl"}}
}

// Requests seen in TLS plaintext (milestone 6.2) are recorded by host,
// method, path and tool, with their statuses, and narrated in the
// timeline; nothing of a body is.
func TestTLSTimeline(t *testing.T) {
	r := newTestRecorder(t)
	r.Meta.Put(RunMeta{RunID: "abc", Command: []string{"agent"}, UID: os.Getuid()})
	tl := feed(t, r,
		runEv(EventRunStart, 0, "/agents/run-abc"),
		tlsEv(1, TLSRequest{Proto: "HTTP/2", Method: "GET", Host: "api.github.com", Path: "/repos/a/b", Status: 200}),
		tlsEv(2, TLSRequest{Proto: "HTTP/2", Method: "GET", Host: "api.github.com", Path: "/repos/a/b", Status: 404}),
		tlsEv(3, TLSRequest{Proto: "HTTP/1.1", Method: "POST", Host: "mcp.example.com", Path: "/mcp", Status: 200, MCPMethod: "tools/call", Tool: "search"}),
		runEv(EventRunEnd, 4, "/agents/run-abc"),
	)
	if len(tl.Summary.TLS) != 2 {
		t.Fatalf("summary: %+v", tl.Summary.TLS)
	}
	gh := tl.Summary.TLS[0]
	if gh.Host != "api.github.com" || gh.Requests != 2 || gh.Statuses[200] != 1 || gh.Statuses[404] != 1 {
		t.Errorf("github: %+v", gh)
	}
	if m := tl.Summary.TLS[1]; m.Tool != "search" || m.MCPMethod != "tools/call" {
		t.Errorf("mcp: %+v", m)
	}
	var notes []string
	for _, e := range tl.Events {
		if e.Type == "tls" {
			notes = append(notes, e.Note)
		}
	}
	if len(notes) != 3 || !strings.Contains(notes[0], "seen in the process (libssl, HTTP/2), status 200") || !strings.Contains(notes[2], "MCP tools/call search") {
		t.Errorf("notes: %q", notes)
	}
}

// Learn drafts what TLS plaintext showed of a host the proxy did not
// terminate as a path rule left commented out; check replays it as path
// rules would decide.
func TestTLSLearnAndCheck(t *testing.T) {
	run := &RunTimeline{RunID: "r1", Complete: true, StartedAt: t0, Command: []string{"agent"},
		Summary: RunSummary{
			DNSNames: []string{"api.github.com"},
			Proxied:  []ProxiedDest{{Host: "api.github.com", Port: 443, Requests: 2, Connects: 2, Tunnels: 2}},
			TLS: []TLSUse{
				{Host: "api.github.com", Method: "GET", Path: "/repos/a/b", Proto: "HTTP/2", Requests: 3, Statuses: map[int]int{200: 3}, Lib: "libssl"},
				{Host: "api.github.com", Method: "DELETE", Path: "/repos/a/b", Proto: "HTTP/2", Requests: 1, Statuses: map[int]int{204: 1}, Lib: "libssl"},
			}}}
	d := LearnProfile("drafted", []*RunTimeline{run})
	var buf bytes.Buffer
	if err := d.WriteYAML(&buf, time.Time{}); err != nil {
		t.Fatal(err)
	}
	y := buf.String()
	for _, want := range []string{"# Seen in the TLS plaintext of the run's processes", "#   DELETE /repos/a/b", "#   GET /repos/a/b",
		`#   http: { paths: ["/repos/a/b"] }`} {
		if !strings.Contains(y, want) {
			t.Errorf("draft lacks %q:\n%s", want, y)
		}
	}
	if strings.Contains(y, "the paths are\n      # unseen") {
		t.Error("draft says the paths are unseen")
	}

	cp := compileOne(t, `kind: AgentProfile
metadata: { name: gh }
spec:
  mode: audit
  egress:
    default: deny
    rules:
      - name: gh-read
        to: { fqdn: ["api.github.com"] }
        http: { methods: [GET], paths: ["/repos/*"] }
        action: allow
`)
	rep := CheckRuns(cp, []*RunTimeline{run})
	var allowed, denied bool
	for _, f := range rep.Allowed {
		allowed = allowed || f.What == "GET api.github.com:443/repos/a/b (seen in the process)"
	}
	for _, f := range rep.Violations {
		denied = denied || f.What == "DELETE api.github.com:443/repos/a/b (seen in the process)"
	}
	if !allowed || !denied {
		t.Errorf("check: allowed %v denied %v\n%+v\n%+v", allowed, denied, rep.Allowed, rep.Violations)
	}
}

// The receipt says observation is audit, and why it may not happen.
func TestObservePlacement(t *testing.T) {
	doc := `kind: AgentProfile
metadata: { name: o }
spec:
  mode: audit
  egress: { default: allow }
  observe: { tls_plaintext: true }
`
	for _, tc := range []struct {
		opts policy.Options
		want string
	}{
		{policy.Options{Linux: true, Uprobes: true}, "uprobes on OpenSSL, BoringSSL, GnuTLS and Go crypto/tls"},
		{policy.Options{Linux: true}, "needs the node agent's -uprobes"},
		{policy.Options{}, "needs the Linux node agent"},
	} {
		p, _ := policy.Parse([]byte(doc))
		c, diags := policy.Compile(tc.opts, p)
		if len(diags) > 0 {
			t.Fatal(diags)
		}
		found := false
		for _, pl := range c.Profiles[0].Placements {
			if pl.Rule == "observe/tls-plaintext" && pl.Tier == "audit" && strings.Contains(pl.EnforcedBy, tc.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%+v: no placement saying %q: %+v", tc.opts, tc.want, c.Profiles[0].Placements)
		}
		if !c.Profiles[0].CapturesTLS() {
			t.Error("CapturesTLS false")
		}
	}
	// Any layer asking is enough: observation is not a permission.
	p, _ := policy.Parse([]byte(doc))
	c, _ := policy.Compile(policy.Options{Linux: true}, p)
	plain, _ := policy.Parse([]byte(strings.Replace(doc, "  observe: { tls_plaintext: true }\n", "", 1)))
	pc, _ := policy.Compile(policy.Options{Linux: true}, plain)
	eff := &policy.Effective{Layers: []policy.Layer{{Profile: pc.Profiles[0]}, {Profile: c.Profiles[0]}}}
	if !eff.CapturesTLS() || (&policy.Effective{Layers: []policy.Layer{{Profile: pc.Profiles[0]}}}).CapturesTLS() {
		t.Error("CapturesTLS across layers")
	}
	// A profile without the block keeps its version.
	if b, _ := json.Marshal(plain); strings.Contains(string(b), "observe") {
		t.Error("an absent observe block appears in the profile's JSON")
	}
}

// Go binaries exec'd in a capturing run are listed once each (milestone
// 6.3), probed or not visible and why, with how often they ran.
func TestTLSProgramTimeline(t *testing.T) {
	r := newTestRecorder(t)
	r.Meta.Put(RunMeta{RunID: "abc", Command: []string{"agent"}, UID: os.Getuid()})
	prog := func(ms int, d TLSProgramData) AuditEvent {
		return AuditEvent{Type: EventTLSProgram, Timestamp: at(ms), CgroupID: testRunCg, RunCgroupID: testRunCg, PID: 11, Data: d}
	}
	gh := TLSProgramData{Path: "/usr/bin/gh", Stack: "go1.26.8 crypto/tls", Lib: "go1.26.8", Probed: true}
	tl := feed(t, r,
		runEv(EventRunStart, 0, "/agents/run-abc"),
		prog(1, gh), prog(2, gh),
		prog(3, TLSProgramData{Path: "/opt/new", Stack: "go1.27.0 crypto/tls", Reason: "Go newer than go1.26, the last tested"}),
		runEv(EventRunEnd, 4, "/agents/run-abc"),
	)
	p := tl.Summary.TLSPrograms
	if len(p) != 2 || p[0].Path != "/opt/new" || p[0].Probed || p[1].Path != "/usr/bin/gh" || !p[1].Probed || p[1].Execs != 2 {
		t.Fatalf("programs: %+v", p)
	}
	var notes []string
	for _, e := range tl.Events {
		if e.Type == "tls-program" {
			notes = append(notes, e.Note)
		}
	}
	if len(notes) != 2 || notes[0] != "go1.26.8 crypto/tls probed" || !strings.Contains(notes[1], "not visible: Go newer") {
		t.Errorf("notes: %q", notes)
	}
}

// A TLS record's host carries its port unless it is 443 (milestone 7.1):
// check replays it on that port, and skips it where the proxy saw the
// same host and port by path.
func TestTLSCheckPort(t *testing.T) {
	run := &RunTimeline{RunID: "r2", Complete: true, StartedAt: t0, Command: []string{"agent"},
		Summary: RunSummary{
			Proxied: []ProxiedDest{{Host: "model.example.com", Port: 8443, Requests: 2, Connects: 1,
				Paths: []PathUse{{Method: "POST", Path: "/v1/messages", Requests: 1}}}},
			TLS: []TLSUse{
				{Host: "model.example.com:8443", Method: "POST", Path: "/v1/messages", Proto: "HTTP/1.1", Requests: 1, Lib: "libssl"},
				{Host: "api.example.com:8443", Method: "GET", Path: "/x", Proto: "HTTP/2", Requests: 1, Lib: "libssl"},
			}}}
	cp := compileOne(t, `kind: AgentProfile
metadata: { name: p }
spec:
  mode: audit
  egress:
    default: deny
    rules:
      - { name: api, to: { fqdn: ["api.example.com"], ports: [8443] }, action: allow }
`)
	rep := CheckRuns(cp, []*RunTimeline{run})
	var allowed bool
	for _, f := range rep.Allowed {
		allowed = allowed || f.What == "GET api.example.com:8443/x (seen in the process)"
	}
	for _, f := range append(rep.Violations, rep.Allowed...) {
		if strings.Contains(f.What, "model.example.com") && strings.Contains(f.What, "seen in the process") {
			t.Errorf("replayed a host the proxy saw by path: %+v", f)
		}
		if strings.Contains(f.What, ":8443:443") {
			t.Errorf("port appended twice: %+v", f)
		}
	}
	if !allowed {
		t.Errorf("not replayed on its own port:\n%+v\n%+v", rep.Allowed, rep.Violations)
	}
}
