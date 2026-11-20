// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"os"
	"reflect"
	"testing"
	"time"
)

const testRunCg = 4242

func newTestRecorder(t *testing.T) *RunRecorder {
	t.Helper()
	r, err := NewRunRecorder(CgroupV2Root+"/agents", t.TempDir(), NewRunRegistry())
	if err != nil {
		t.Fatal(err)
	}
	r.lookupPath = func(id uint64) string {
		if id == testRunCg {
			return "/agents/run-abc"
		}
		return ""
	}
	return r
}

var t0 = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

func at(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }

func runEv(typ int, ms int, path string) AuditEvent {
	return AuditEvent{Type: typ, Timestamp: at(ms), CgroupID: testRunCg, RunCgroupID: testRunCg, Data: RunData{CgroupPath: path}}
}

func execEv(ms int, cg uint64, pid, ppid uint32, bin string, args ...string) AuditEvent {
	return AuditEvent{Type: EventExec, Timestamp: at(ms), CgroupID: cg, RunCgroupID: testRunCg, PID: pid,
		Data: ExecData{BinaryPath: bin, PID: pid, PPID: ppid, Args: args}}
}

func connEv(ms int, pid uint32, ip string, port uint16) AuditEvent {
	return AuditEvent{Type: EventConnect, Timestamp: at(ms), CgroupID: testRunCg, RunCgroupID: testRunCg, PID: pid,
		Data: ConnectData{DstIP: ip, DstPort: port, Protocol: "TCP"}}
}

func feed(t *testing.T, r *RunRecorder, evs ...AuditEvent) *RunTimeline {
	t.Helper()
	var last *RunTimeline
	for _, ev := range evs {
		tl, err := r.Handle(ev)
		if err != nil {
			t.Fatal(err)
		}
		if tl != nil {
			last = tl
		}
	}
	return last
}

func TestRunRecorderCompleteRun(t *testing.T) {
	r := newTestRecorder(t)
	exit := 3
	r.Meta.Put(RunMeta{RunID: "abc", Command: []string{"sh", "-c", "curl x"}, UID: os.Getuid(), ExitCode: &exit})

	tl := feed(t, r,
		runEv(EventRunStart, 0, "/agents/run-abc"),
		execEv(1, testRunCg, 10, 9, "/bin/sh", "sh", "-c", "curl x"),
		execEv(2, 5555, 11, 10, "/usr/bin/curl", "curl", "x"), // child cgroup rolls up
		connEv(3, 11, "1.2.3.4", 443),
		connEv(4, 11, "1.2.3.4", 443),
		connEv(5, 11, "::1", 80),
		runEv(EventRunEnd, 6, "/agents/run-abc"),
	)
	if tl == nil {
		t.Fatal("run end produced no timeline")
	}
	if !tl.Complete || tl.RunID != "abc" || tl.ExitCode == nil || *tl.ExitCode != 3 || len(tl.Command) != 3 {
		t.Fatalf("bad metadata: %+v", tl)
	}
	if tl.EndedAt == nil || tl.EndedAt.Sub(tl.StartedAt) != 6*time.Millisecond {
		t.Fatalf("bad times: %v %v", tl.StartedAt, tl.EndedAt)
	}
	if tl.Summary.Execs != 2 || tl.Summary.Connects != 3 || len(tl.Events) != 5 {
		t.Fatalf("bad counts: %+v, %d events", tl.Summary, len(tl.Events))
	}
	if want := []string{"/bin/sh", "/usr/bin/curl"}; !reflect.DeepEqual(tl.Summary.Binaries, want) {
		t.Fatalf("binaries %v, want %v", tl.Summary.Binaries, want)
	}
	want := []Destination{{Proto: "TCP", IP: "1.2.3.4", Port: 443, Count: 2}, {Proto: "TCP", IP: "::1", Port: 80, Count: 1}}
	if !reflect.DeepEqual(tl.Summary.Destinations, want) {
		t.Fatalf("destinations %v, want %v", tl.Summary.Destinations, want)
	}

	// Written to disk, round-trips, and the spool entry is consumed.
	got, err := ReadRunTimeline(TimelinePath(r.OutDir, "abc"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Summary, tl.Summary) || len(got.Events) != 5 {
		t.Fatalf("round trip mismatch")
	}
	if _, ok := r.Meta.Get("abc"); ok {
		t.Fatal("run metadata not released")
	}
	if len(r.runs) != 0 {
		t.Fatalf("run state leaked")
	}
}

func TestRunRecorderIgnoresCgroupsOutsideAgents(t *testing.T) {
	r := newTestRecorder(t)
	feed(t, r, runEv(EventRunStart, 0, "/system.slice/foo"))
	if tl := feed(t, r, runEv(EventRunEnd, 1, "/system.slice/foo")); tl != nil {
		t.Fatal("recorded a cgroup outside agents/")
	}
	if len(r.runs) != 0 {
		t.Fatal("tracked a cgroup outside agents/")
	}
}

func TestRunRecorderRestartResumesPartial(t *testing.T) {
	r := newTestRecorder(t)
	feed(t, r,
		runEv(EventRunStart, 0, "/agents/run-abc"),
		execEv(1, testRunCg, 10, 9, "/bin/sh"),
		connEv(2, 10, "1.2.3.4", 443),
	)
	if errs := r.Flush(); len(errs) != 0 {
		t.Fatal(errs)
	}
	partial, err := ReadRunTimeline(TimelinePath(r.OutDir, "abc"))
	if err != nil || partial.EndedAt != nil || partial.Complete {
		t.Fatalf("bad partial: %+v %v", partial, err)
	}

	// A new node agent picks the run up mid-flight.
	r2 := newTestRecorder(t)
	r2.OutDir = r.OutDir
	tl := feed(t, r2,
		connEv(10, 10, "1.2.3.4", 443),
		execEv(11, testRunCg, 12, 10, "/bin/true"),
		runEv(EventRunEnd, 12, "/agents/run-abc"),
	)
	if tl == nil || tl.Complete {
		t.Fatalf("resumed run must be marked incomplete: %+v", tl)
	}
	if !tl.StartedAt.Equal(at(0)) {
		t.Fatalf("lost original start time: %v", tl.StartedAt)
	}
	if tl.Summary.Execs != 2 || tl.Summary.Connects != 2 || tl.Summary.Destinations[0].Count != 2 {
		t.Fatalf("summary not merged: %+v", tl.Summary)
	}
	types := []string{}
	for _, e := range tl.Events {
		types = append(types, e.Type)
	}
	if want := []string{"exec", "connect", "gap", "connect", "exec"}; !reflect.DeepEqual(types, want) {
		t.Fatalf("events %v, want %v", types, want)
	}
}

func TestRunRecorderUnknownRunUsesLookup(t *testing.T) {
	r := newTestRecorder(t)
	tl := feed(t, r,
		execEv(1, testRunCg, 10, 9, "/bin/sh"),
		runEv(EventRunEnd, 2, "/agents/run-abc"),
	)
	if tl == nil || tl.RunID != "abc" || tl.Complete || tl.Events[0].Type != "gap" {
		t.Fatalf("bad timeline: %+v", tl)
	}
}

func TestRunRecorderEventCap(t *testing.T) {
	r := newTestRecorder(t)
	r.MaxEvents = 2
	tl := feed(t, r,
		runEv(EventRunStart, 0, "/agents/run-abc"),
		connEv(1, 10, "1.1.1.1", 53),
		connEv(2, 10, "1.1.1.1", 53),
		connEv(3, 10, "1.1.1.1", 53),
		runEv(EventRunEnd, 4, "/agents/run-abc"),
	)
	if len(tl.Events) != 2 || tl.DroppedEvents != 1 || tl.Summary.Connects != 3 || tl.Summary.Destinations[0].Count != 3 {
		t.Fatalf("cap not applied: %d events, %d dropped, %+v", len(tl.Events), tl.DroppedEvents, tl.Summary)
	}
}

func TestSplitArgs(t *testing.T) {
	cases := map[string][]string{
		"":                   nil,
		"sh\x00-c\x00ls\x00": {"sh", "-c", "ls"},
		"curl\x00http://ex":  {"curl", "http://ex"}, // cut at the capture limit
		"a\x00\x00b\x00":     {"a", "", "b"},
	}
	for in, want := range cases {
		if got := splitArgs([]byte(in)); !reflect.DeepEqual(got, want) {
			t.Errorf("splitArgs(%q) = %q, want %q", in, got, want)
		}
	}
}
