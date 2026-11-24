// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	sumA = "sha256:aa00000000000000000000000000000000000000000000000000000000000001"
	sumB = "sha256:bb00000000000000000000000000000000000000000000000000000000000002"
)

func execPathEv(ms int, d ExecPathData) AuditEvent {
	return AuditEvent{Type: EventExecPath, Timestamp: at(ms), CgroupID: testRunCg, RunCgroupID: testRunCg, PID: 10, Data: d}
}

// The timeline keeps each content's hash, and narrates a refusal by
// content.
func TestExecHashTimeline(t *testing.T) {
	r := newTestRecorder(t)
	r.Meta.Put(RunMeta{RunID: "abc", Command: []string{"tool"}, UID: os.Getuid()})
	tl := feed(t, r,
		runEv(EventRunStart, 0, "/agents/run-abc"),
		execPathEv(1, ExecPathData{Path: "/opt/tool", Verdict: "allowed", Hash: sumA}),
		execPathEv(2, ExecPathData{Path: "/opt/tool", Verdict: "exec: denied", Hash: sumB, HashMismatch: true}),
		execPathEv(3, ExecPathData{Path: "/opt/other", Verdict: "exec: denied", HashError: true}),
		runEv(EventRunEnd, 4, "/agents/run-abc"),
	)
	if len(tl.Summary.Exec) != 3 || tl.Summary.Exec[0].Hash != sumA || !tl.Summary.Exec[1].HashMismatch || !tl.Summary.Exec[2].HashError {
		t.Fatalf("summary: %+v", tl.Summary.Exec)
	}
	var notes []string
	for _, e := range tl.Events {
		if e.Type == "exec_path" {
			notes = append(notes, e.Note)
		}
	}
	if len(notes) != 2 || !strings.Contains(notes[0], sumB+" is not a hash exec.allow lists") || !strings.Contains(notes[1], "could not be hashed") {
		t.Errorf("notes: %q", notes)
	}
}

func hashedRun(id string, uses ...ExecUse) *RunTimeline {
	return &RunTimeline{RunID: id, Complete: true, StartedAt: t0, Command: []string{"tool"},
		Summary: RunSummary{Binaries: []string{"/opt/tool"}, Exec: uses}}
}

// Check decides a pinned path by the recorded content, and calls a path
// recorded without content unverifiable rather than guessing.
func TestCheckExecHash(t *testing.T) {
	cp := compileOne(t, `kind: AgentProfile
metadata: { name: pin }
spec:
  mode: audit
  egress: { default: deny }
  exec:
    default: deny
    allow:
      - { path: /opt/tool, hash: "`+sumA+`" }
      - { path: /usr/bin/env }
`)
	runs := []*RunTimeline{
		hashedRun("r1", ExecUse{Path: "/opt/tool", Verdict: "allowed", Hash: sumA}, ExecUse{Path: "/usr/bin/env", Trusted: true, Verdict: "allowed"}),
		hashedRun("r2", ExecUse{Path: "/opt/tool", Verdict: "exec: denied", Hash: sumB, HashMismatch: true}),
		hashedRun("r3", ExecUse{Path: "/opt/tool", Verdict: "allowed"}),
	}
	rep := CheckRuns(cp, runs)
	find := func(list []CheckFinding, what string) *CheckFinding {
		for i := range list {
			if list[i].What == what {
				return &list[i]
			}
		}
		return nil
	}
	if f := find(rep.Allowed, "/opt/tool ("+sumA+")"); f == nil || f.Rule != "exec.allow" {
		t.Errorf("pinned content not allowed: %+v", rep.Allowed)
	}
	if f := find(rep.Violations, "/opt/tool ("+sumB+")"); f == nil || !strings.Contains(f.Message, "content is not a hash") {
		t.Errorf("other content not a violation: %+v", rep.Violations)
	}
	if f := find(rep.Unverifiable, "/opt/tool (content not recorded)"); f == nil || len(f.Runs) != 1 || f.Runs[0] != "r3" {
		t.Errorf("unhashed record not unverifiable: %+v", rep.Unverifiable)
	}
	if find(rep.Allowed, "/usr/bin/env") == nil {
		t.Errorf("plain entry: %+v", rep.Allowed)
	}
}

// Learn drafts the contents the kernel recorded for a pinned path, one
// entry each, and the draft checks clean against its runs.
func TestLearnExecHash(t *testing.T) {
	runs := []*RunTimeline{
		hashedRun("r1", ExecUse{Path: "/opt/tool", Verdict: "allowed", Hash: sumA}),
		hashedRun("r2", ExecUse{Path: "/opt/tool", Verdict: "allowed", Hash: sumB}, ExecUse{Path: "/usr/bin/env", Trusted: true, Verdict: "allowed"}),
	}
	d := LearnProfile("drafted", runs)
	var buf bytes.Buffer
	if err := d.WriteYAML(&buf, time.Time{}); err != nil {
		t.Fatal(err)
	}
	y := buf.String()
	for _, want := range []string{
		"- path: \"/opt/tool\"", "hash: \"" + sumA + "\"", "hash: \"" + sumB + "\"",
		"add hash: sha256:<sha256sum of the file>",
	} {
		if !strings.Contains(y, want) {
			t.Errorf("draft lacks %q:\n%s", want, y)
		}
	}
	if n := strings.Count(y, "- path: \"/opt/tool\""); n != 2 {
		t.Errorf("/opt/tool listed %d times, want 2", n)
	}
	cp := compileOne(t, y)
	if rep := CheckRuns(cp, runs); len(rep.Violations) > 0 || len(rep.Unverifiable) > 0 {
		t.Errorf("draft fails its own runs: %+v %+v", rep.Violations, rep.Unverifiable)
	}
}
