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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DefaultMaxRunEvents bounds the events kept per run. Events past the cap
// are counted in DroppedEvents and still reflected in the summary.
const DefaultMaxRunEvents = 100000

// RunTimeline is the exported record of one run: its metadata, a summary
// suitable for drafting a profile, and the ordered events.
type RunTimeline struct {
	RunID      string     `json:"run_id"`
	CgroupID   uint64     `json:"cgroup_id"`
	CgroupPath string     `json:"cgroup_path,omitempty"`
	Command    []string   `json:"command,omitempty"`
	Cwd        string     `json:"cwd,omitempty"`
	UID        *int       `json:"uid,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	EndedAt    *time.Time `json:"ended_at,omitempty"`
	ExitCode   *int       `json:"exit_code,omitempty"`

	// Complete is true only if the node agent saw the run from cgroup
	// creation to removal without interruption. Otherwise events may be
	// missing; gaps are marked with "gap" events.
	Complete      bool `json:"complete"`
	DroppedEvents int  `json:"dropped_events,omitempty"`

	Summary RunSummary      `json:"summary"`
	Events  []TimelineEvent `json:"events"`
}

// RunSummary aggregates a run's events.
type RunSummary struct {
	Execs        int           `json:"execs"`
	Connects     int           `json:"connects"`
	DNSReplies   int           `json:"dns_replies"`
	Binaries     []string      `json:"binaries"`
	DNSNames     []string      `json:"dns_names"` // distinct names looked up
	Destinations []Destination `json:"destinations"`
}

// Destination is one distinct (protocol, address, port) a run connected to.
type Destination struct {
	Proto string `json:"proto"`
	IP    string `json:"ip"`
	Port  uint16 `json:"port"`
	Count int    `json:"count"`
	// Names are the looked-up names that resolved to IP, within this run,
	// before a connect to it. Empty if the run connected to a literal IP
	// or resolved it some way DNS capture does not see.
	Names []string `json:"names,omitempty"`
}

// TimelineEvent is one entry in a run's timeline.
type TimelineEvent struct {
	Time     time.Time   `json:"time"`
	Type     string      `json:"type"` // exec, connect, dns, gap
	PID      uint32      `json:"pid,omitempty"`
	PPID     uint32      `json:"ppid,omitempty"`
	CgroupID uint64      `json:"cgroup_id,omitempty"`
	Binary   string      `json:"binary,omitempty"`
	Args     []string    `json:"args,omitempty"`
	Proto    string      `json:"proto,omitempty"`
	DstIP    string      `json:"dst_ip,omitempty"`
	DstPort  uint16      `json:"dst_port,omitempty"`
	DstName  string      `json:"dst_name,omitempty"` // from an earlier DNS reply
	Query    string      `json:"query,omitempty"`
	QType    string      `json:"qtype,omitempty"`
	RCode    string      `json:"rcode,omitempty"`
	Server   string      `json:"server,omitempty"`
	Answers  []DNSAnswer `json:"answers,omitempty"`
	Partial  bool        `json:"partial,omitempty"` // DNS reply cut off at capture limit
	Note     string      `json:"note,omitempty"`
}

type destKey struct {
	proto string
	ip    string
	port  uint16
}

type runState struct {
	tl       *RunTimeline
	sawStart bool
	gap      bool
	binaries map[string]struct{}
	dests    map[destKey]*destState
	names    map[string]struct{}
	// ipName maps an address to the name whose lookup most recently
	// returned it in this run.
	ipName map[string]string
}

type destState struct {
	count int
	names map[string]struct{}
}

// RunRecorder groups audit events by run and writes one timeline file per
// run when its cgroup is removed. It is not safe for concurrent use; feed
// it from a single goroutine.
type RunRecorder struct {
	OutDir    string
	MaxEvents int
	// Meta supplies what the run API knows about runs; may be nil.
	Meta *RunRegistry

	// agentsRel is the agents dir relative to the cgroup root, e.g. /agents.
	agentsRel string
	// lookupPath finds the cgroup path of a run first seen mid-flight
	// (node agent started after the run). Replaceable for tests.
	lookupPath func(cgroupID uint64) string

	runs map[uint64]*runState
}

// NewRunRecorder returns a recorder for runs under agentsDir.
func NewRunRecorder(agentsDir, outDir string, meta *RunRegistry) (*RunRecorder, error) {
	rel, err := filepath.Rel(CgroupV2Root, agentsDir)
	if err != nil || strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("%s is not under %s", agentsDir, CgroupV2Root)
	}
	// World-listable: each timeline file is owned by, and readable only
	// by, the user who started the run (and root).
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create %s: %w", outDir, err)
	}
	return &RunRecorder{
		OutDir:     outDir,
		Meta:       meta,
		MaxEvents:  DefaultMaxRunEvents,
		agentsRel:  "/" + rel,
		lookupPath: func(id uint64) string { return findRunCgroupPath(agentsDir, id) },
		runs:       make(map[uint64]*runState),
	}, nil
}

// findRunCgroupPath returns the cgroup-root-relative path of the run
// cgroup under agentsDir with the given id, or "".
func findRunCgroupPath(agentsDir string, id uint64) string {
	entries, err := os.ReadDir(agentsDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		p := filepath.Join(agentsDir, e.Name())
		if e.IsDir() {
			if got, err := GetCgroupID(p); err == nil && got == id {
				rel, _ := filepath.Rel(CgroupV2Root, p)
				return "/" + rel
			}
		}
	}
	return ""
}

// runIDFor derives the run id from a run cgroup path. Cgroups under agents/
// that agentctl did not name run-<id> are identified by cgroup id.
func (r *RunRecorder) runIDFor(path string, cgroupID uint64) string {
	if strings.HasPrefix(path, r.agentsRel+"/"+RunPrefix) {
		if id := strings.TrimPrefix(path, r.agentsRel+"/"+RunPrefix); id != "" && !strings.Contains(id, "/") {
			return id
		}
	}
	return fmt.Sprintf("cg-%d", cgroupID)
}

func (r *RunRecorder) underAgents(path string) bool {
	return strings.HasPrefix(path, r.agentsRel+"/")
}

func (r *RunRecorder) timelinePath(runID string) string {
	return TimelinePath(r.OutDir, runID)
}

// state returns the run for ev, creating it if needed. A run first seen
// without its start event either resumes the partial timeline written
// before a node agent restart, or starts fresh; both are marked as gaps.
func (r *RunRecorder) state(ev AuditEvent, path string) *runState {
	id := ev.RunCgroupID
	if st, ok := r.runs[id]; ok {
		return st
	}
	if path == "" {
		path = r.lookupPath(id)
	}
	runID := r.runIDFor(path, id)

	st := &runState{
		tl: &RunTimeline{
			RunID:      runID,
			CgroupID:   id,
			CgroupPath: path,
			StartedAt:  ev.Timestamp,
			Events:     []TimelineEvent{},
		},
		binaries: make(map[string]struct{}),
		dests:    make(map[destKey]*destState),
		names:    make(map[string]struct{}),
		ipName:   make(map[string]string),
	}
	if ev.Type == EventRunStart {
		st.sawStart = true
	} else {
		if prev, err := ReadRunTimeline(r.timelinePath(runID)); err == nil && prev.CgroupID == id && prev.EndedAt == nil {
			st.tl = prev
			for _, b := range prev.Summary.Binaries {
				st.binaries[b] = struct{}{}
			}
			for _, n := range prev.Summary.DNSNames {
				st.names[n] = struct{}{}
			}
			for _, d := range prev.Summary.Destinations {
				ds := &destState{count: d.Count, names: make(map[string]struct{})}
				for _, n := range d.Names {
					ds.names[n] = struct{}{}
					st.ipName[d.IP] = n
				}
				st.dests[destKey{d.Proto, d.IP, d.Port}] = ds
			}
		}
		st.gap = true
		st.tl.Events = append(st.tl.Events, TimelineEvent{
			Time: ev.Timestamp,
			Type: "gap",
			Note: "node agent was not running; earlier events may be missing",
		})
	}
	r.runs[id] = st
	return st
}

func (st *runState) add(te TimelineEvent, max int) {
	if max > 0 && len(st.tl.Events) >= max {
		st.tl.DroppedEvents++
		return
	}
	st.tl.Events = append(st.tl.Events, te)
}

// Handle records ev. When ev ends a run, the run's timeline is written and
// returned.
func (r *RunRecorder) Handle(ev AuditEvent) (*RunTimeline, error) {
	switch ev.Type {
	case EventRunStart:
		d := ev.Data.(RunData)
		if !r.underAgents(d.CgroupPath) {
			return nil, nil
		}
		if _, ok := r.runs[ev.RunCgroupID]; ok {
			return nil, nil // cgroup ids are not reused while alive
		}
		r.state(ev, d.CgroupPath)

	case EventRunEnd:
		d := ev.Data.(RunData)
		if !r.underAgents(d.CgroupPath) {
			return nil, nil
		}
		st := r.state(ev, d.CgroupPath)
		end := ev.Timestamp
		st.tl.EndedAt = &end
		delete(r.runs, ev.RunCgroupID)
		return r.finish(st)

	case EventExec:
		d := ev.Data.(ExecData)
		st := r.state(ev, "")
		st.tl.Summary.Execs++
		st.binaries[d.BinaryPath] = struct{}{}
		st.add(TimelineEvent{
			Time:     ev.Timestamp,
			Type:     "exec",
			PID:      ev.PID,
			PPID:     d.PPID,
			CgroupID: ev.CgroupID,
			Binary:   d.BinaryPath,
			Args:     d.Args,
		}, r.MaxEvents)

	case EventConnect:
		d := ev.Data.(ConnectData)
		st := r.state(ev, "")
		st.tl.Summary.Connects++
		k := destKey{d.Protocol, d.DstIP, d.DstPort}
		ds := st.dests[k]
		if ds == nil {
			ds = &destState{names: make(map[string]struct{})}
			st.dests[k] = ds
		}
		ds.count++
		name := st.ipName[d.DstIP]
		if name != "" {
			ds.names[name] = struct{}{}
		}
		st.add(TimelineEvent{
			Time:     ev.Timestamp,
			Type:     "connect",
			PID:      ev.PID,
			CgroupID: ev.CgroupID,
			Proto:    d.Protocol,
			DstIP:    d.DstIP,
			DstPort:  d.DstPort,
			DstName:  name,
		}, r.MaxEvents)

	case EventDNS:
		d := ev.Data.(DNSData)
		st := r.state(ev, "")
		st.tl.Summary.DNSReplies++
		if d.Query != "" {
			st.names[d.Query] = struct{}{}
			for _, ip := range d.Addrs() {
				st.ipName[ip] = d.Query
			}
		}
		st.add(TimelineEvent{
			Time:     ev.Timestamp,
			Type:     "dns",
			CgroupID: ev.CgroupID,
			Query:    d.Query,
			QType:    d.QType,
			RCode:    d.RCode,
			Server:   d.Server,
			Answers:  d.Answers,
			Partial:  d.Partial,
		}, r.MaxEvents)
	}
	return nil, nil
}

// Flush writes every run still in progress as a partial timeline (no
// ended_at). A node agent restarted later resumes appending to it.
func (r *RunRecorder) Flush() []error {
	var errs []error
	for id, st := range r.runs {
		if _, err := r.write(st); err != nil {
			errs = append(errs, err)
		}
		delete(r.runs, id)
	}
	return errs
}

// finish writes a finished run and releases its metadata.
func (r *RunRecorder) finish(st *runState) (*RunTimeline, error) {
	st.tl.Complete = st.sawStart && !st.gap
	tl, err := r.write(st)
	if r.Meta != nil {
		r.Meta.Done(st.tl.RunID)
	}
	return tl, err
}

// mergeMeta copies what the run API knows into the timeline.
func (r *RunRecorder) mergeMeta(tl *RunTimeline) {
	if r.Meta == nil {
		return
	}
	m, ok := r.Meta.Get(tl.RunID)
	if !ok {
		return
	}
	tl.Command = m.Command
	tl.Cwd = m.Cwd
	uid := m.UID
	tl.UID = &uid
	if m.ExitCode != nil {
		tl.ExitCode = m.ExitCode
	}
}

func (r *RunRecorder) write(st *runState) (*RunTimeline, error) {
	tl := st.tl
	r.mergeMeta(tl)
	tl.Summary.Binaries = sortedKeys(st.binaries)

	tl.Summary.DNSNames = sortedKeys(st.names)

	tl.Summary.Destinations = make([]Destination, 0, len(st.dests))
	for k, ds := range st.dests {
		tl.Summary.Destinations = append(tl.Summary.Destinations, Destination{
			Proto: k.proto, IP: k.ip, Port: k.port, Count: ds.count,
		})
		if len(ds.names) > 0 {
			tl.Summary.Destinations[len(tl.Summary.Destinations)-1].Names = sortedKeys(ds.names)
		}
	}
	sort.Slice(tl.Summary.Destinations, func(i, j int) bool {
		a, b := tl.Summary.Destinations[i], tl.Summary.Destinations[j]
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Proto < b.Proto
	})

	data, err := json.MarshalIndent(tl, "", "  ")
	if err != nil {
		return nil, err
	}
	uid := -1
	if tl.UID != nil {
		uid = *tl.UID
	}
	if err := writeFileAtomicOwned(r.timelinePath(tl.RunID), append(data, '\n'), 0600, uid); err != nil {
		return nil, fmt.Errorf("failed to write timeline for run %s: %w", tl.RunID, err)
	}
	return tl, nil
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ReadRunTimeline reads an exported timeline file.
func ReadRunTimeline(path string) (*RunTimeline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tl RunTimeline
	if err := json.Unmarshal(data, &tl); err != nil {
		return nil, fmt.Errorf("bad timeline %s: %w", path, err)
	}
	if tl.Events == nil {
		tl.Events = []TimelineEvent{}
	}
	return &tl, nil
}

// TimelinePath returns where the timeline for runID lives in outDir.
func TimelinePath(outDir, runID string) string {
	return filepath.Join(outDir, "run-"+runID+".json")
}
