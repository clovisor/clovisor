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
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
	Policy     *RunPolicy `json:"policy,omitempty"`

	// Complete is true only if the node agent saw the run from cgroup
	// creation to removal without interruption. Otherwise events may be
	// missing; gaps are marked with "gap" events.
	Complete      bool `json:"complete"`
	DroppedEvents int  `json:"dropped_events,omitempty"`
	// LostEvents were lost in the kernel, the ring buffer being full
	// (milestone 3.5). A run that lost any is not complete.
	LostEvents uint64 `json:"lost_events,omitempty"`
	// SuppressedEvents were not reported because the run produced events
	// faster than its budget allows (so that it cannot crowd other runs out
	// of the ring buffer). Enforcement was unaffected; the timeline is not
	// complete.
	SuppressedEvents uint64 `json:"suppressed_events,omitempty"`

	Summary RunSummary `json:"summary"`
	// Calls are the run's tool calls and MCP servers, each with a cgroup of
	// its own (milestone 4.5), and what happened in them.
	Calls  []CallSummary   `json:"calls,omitempty"`
	Events []TimelineEvent `json:"events"`
}

// CallSummary is one tool call or MCP server, from the run API's record
// and the events attributed to its cgroup.
type CallSummary struct {
	CallMeta
	// Events counts the events attributed to the call, by type (exec,
	// connect, http, dns, ...); Refused those that were refused.
	Events  map[string]int `json:"events,omitempty"`
	Refused int            `json:"refused,omitempty"`
}

// RunSummary aggregates a run's events.
type RunSummary struct {
	Execs      int      `json:"execs"`
	Connects   int      `json:"connects"`
	DNSReplies int      `json:"dns_replies"`
	Binaries   []string `json:"binaries"`
	DNSNames   []string `json:"dns_names"` // distinct names looked up and answered
	// DNSBlocked are names the node's resolver refused to resolve
	// (milestone 3.4); they never left the node.
	DNSBlocked   []string      `json:"dns_blocked,omitempty"`
	Destinations []Destination `json:"destinations"`
	// Proxied is what the run asked the node's proxy for, by destination.
	// Connections to the proxy itself are counted in ProxyConnects and
	// not listed as destinations.
	Proxied       []ProxiedDest `json:"proxied,omitempty"`
	ProxyConnects int           `json:"proxy_connects,omitempty"`
	// Redirected counts connects transparent mode sent to the proxy
	// (milestone 3.1); what they were for arrives as http events, so they
	// are not listed as destinations. Refused counts connects refused
	// because the node agent was down.
	Redirected int `json:"redirected,omitempty"`
	Refused    int `json:"refused,omitempty"`
	// UDPRefused counts refused UDP sends (milestone 3.3): one per connect,
	// or per unconnected socket. Dropped counts packets the egress
	// backstop dropped.
	UDPRefused int `json:"udp_refused,omitempty"`
	Dropped    int `json:"dropped,omitempty"`
	// SocketsRefused counts sockets the BPF LSM hooks refused: unusual
	// families and raw sockets, and network sockets created outside the
	// run (milestones 4.1, 4.3). In audit, those that would have been.
	SocketsRefused int `json:"sockets_refused,omitempty"`
	// Unix lists Unix sockets outside the run the run used, with what was
	// done (milestone 4.2): refused, or in audit would have been. Each is
	// reported once per run.
	Unix []UnixUse `json:"unix,omitempty"`
	// Exec lists the resolved paths the kernel ran, with whether each
	// passed the trusted-path test and what was done (milestone 4.4).
	// Each path appears once per verdict. Where BPF LSM is not active it is
	// empty, and Binaries is all there is.
	Exec []ExecUse `json:"exec,omitempty"`
	// UDPRefusedTo is where refused UDP was sent, by destination: what a
	// reviewer weighs against the node's -udp-allow (milestone 3.6).
	UDPRefusedTo []Destination `json:"udp_refused_to,omitempty"`
	// MCP is what the run did through the local MCP gateway.
	MCP []MCPUse `json:"mcp,omitempty"`
}

// MCPUse aggregates gateway operations on one tool or resource.
type MCPUse struct {
	Server    string `json:"server"`
	Method    string `json:"method"` // tools/call, resources/read, ...
	Name      string `json:"name,omitempty"`
	Calls     int    `json:"calls"`
	Denied    int    `json:"denied,omitempty"`
	WouldDeny int    `json:"would_deny,omitempty"`
}

// ProxiedDest aggregates proxied requests to one destination.
type ProxiedDest struct {
	Host      string `json:"host"` // hostname or IP literal
	Port      uint16 `json:"port"`
	Requests  int    `json:"requests"`
	Denied    int    `json:"denied,omitempty"`     // blocked
	WouldDeny int    `json:"would_deny,omitempty"` // allowed, but an audit layer would deny
	// Tunnels counts CONNECTs let through without termination: what went
	// inside them is unseen, so the host was used without path limits.
	Tunnels int `json:"tunnels,omitempty"`
	// Connects counts every CONNECT, so that Requests minus Connects is
	// the requests recorded by path.
	Connects int `json:"connects,omitempty"`
	// Transparent counts requests the connect hooks redirected here;
	// AddrMismatches those sent to an address the name does not resolve
	// to (they reached the name's address instead).
	Transparent    int `json:"transparent,omitempty"`
	AddrMismatches int `json:"addr_mismatches,omitempty"`
	// Paths are the requests the proxy saw by method and path: plain HTTP,
	// and requests inside terminated tunnels. At most MaxPaths distinct
	// entries are kept; requests beyond that are counted in PathsDropped.
	Paths        []PathUse `json:"paths,omitempty"`
	PathsDropped int       `json:"paths_dropped,omitempty"`
}

// PathUse aggregates proxied requests with one method and path.
type PathUse struct {
	Method    string `json:"method"`
	Path      string `json:"path"`
	Requests  int    `json:"requests"`
	Denied    int    `json:"denied,omitempty"`
	WouldDeny int    `json:"would_deny,omitempty"`
}

// MaxPaths bounds the distinct method and path pairs kept per proxied
// destination, since paths carry ids and a run controls them.
const MaxPaths = 256

func (pd *ProxiedDest) addRequest(d HTTPData) {
	pd.Requests++
	if d.Transparent {
		pd.Transparent++
	}
	if d.AddrMismatch {
		pd.AddrMismatches++
	}
	blocked := d.Decision == "deny" && d.Enforced
	if blocked {
		pd.Denied++
	} else if len(d.WouldDeny) > 0 {
		pd.WouldDeny++
	}
	if d.Method == "CONNECT" {
		pd.Connects++
		if !blocked && !d.Terminated {
			pd.Tunnels++
		}
		return
	}
	var u *PathUse
	for i := range pd.Paths {
		if pd.Paths[i].Method == d.Method && pd.Paths[i].Path == d.Path {
			u = &pd.Paths[i]
			break
		}
	}
	if u == nil {
		if len(pd.Paths) >= MaxPaths {
			pd.PathsDropped++
			return
		}
		pd.Paths = append(pd.Paths, PathUse{Method: d.Method, Path: d.Path})
		u = &pd.Paths[len(pd.Paths)-1]
	}
	u.Requests++
	if blocked {
		u.Denied++
	} else if len(d.WouldDeny) > 0 {
		u.WouldDeny++
	}
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
	Type     string      `json:"type"` // exec, exec_path, connect, dns, http, mcp, drop, socket, unix, gap
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
	// http events (proxied requests):
	Method    string   `json:"method,omitempty"`
	Path      string   `json:"path,omitempty"`
	Decision  string   `json:"decision,omitempty"`
	Enforced  bool     `json:"enforced,omitempty"`
	Rule      string   `json:"rule,omitempty"`
	Layer     string   `json:"layer,omitempty"`
	WouldDeny []string `json:"would_deny,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	// Transparent marks traffic the connect hooks redirected; OrigDst is
	// the address the run connected to, SNI its TLS server name.
	Transparent  bool   `json:"transparent,omitempty"`
	OrigDst      string `json:"orig_dst,omitempty"`
	SNI          string `json:"sni,omitempty"`
	AddrMismatch bool   `json:"addr_mismatch,omitempty"`
	// ResolvedName: decided by this name, which the node's resolver had
	// answered with the address for this run.
	ResolvedName string `json:"resolved_name,omitempty"`
	// Verdict is what transparent mode did with a connect.
	Verdict string `json:"verdict,omitempty"`
	// Call is the tool call or MCP server the event came from (milestone
	// 4.5), when it came from one.
	Call string `json:"call,omitempty"`
	// mcp events:
	MCPServer string `json:"mcp_server,omitempty"`
	MCPName   string `json:"mcp_name,omitempty"` // tool or resource
	Note      string `json:"note,omitempty"`
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
	udpDeny  map[destKey]*destState // refused UDP
	names    map[string]struct{}
	blocked  map[string]struct{} // names the resolver refused
	// ipName maps an address to the name whose lookup most recently
	// returned it in this run.
	ipName  map[string]string
	proxied map[proxKey]*ProxiedDest
	mcp     map[mcpKey]*MCPUse
	// callFor names the call a cgroup belongs to; calls counts events
	// per call.
	callFor func(cgroupID uint64) string
	calls   map[string]*CallSummary
}

type mcpKey struct{ server, method, name string }

type proxKey struct {
	host string
	port uint16
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
	// LostFor returns, and clears, the kernel events a run lost and those
	// suppressed by its event budget.
	LostFor func(runCg uint64) (lost, suppressed uint64)
	// ProxyAddrs are the node proxy's listen addresses ("ip:port").
	ProxyAddrs map[string]bool

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

// NewCredentialRunRecorder records runs with credential identity, whose
// start and end the run API reports under CredentialRunsDir.
func NewCredentialRunRecorder(outDir string, meta *RunRegistry) (*RunRecorder, error) {
	return NewRunRecorder(filepath.Join(CgroupV2Root, CredentialRunsDir), outDir, meta)
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
		udpDeny:  make(map[destKey]*destState),
		names:    make(map[string]struct{}),
		blocked:  make(map[string]struct{}),
		ipName:   make(map[string]string),
		proxied:  make(map[proxKey]*ProxiedDest),
		mcp:      make(map[mcpKey]*MCPUse),
		calls:    make(map[string]*CallSummary),
		callFor: func(cg uint64) string {
			if r.Meta == nil {
				return ""
			}
			return r.Meta.CallFor(cg)
		},
	}
	if ev.Type == EventRunStart {
		st.sawStart = true
	} else {
		prev, err := ReadRunTimeline(r.timelinePath(runID))
		if err == nil && prev.CgroupID == id && prev.EndedAt != nil {
			// The run already finished and its timeline is written. A late
			// event must not start a phantom run whose partial timeline
			// would later overwrite the complete one.
			return nil
		}
		if err == nil && prev.CgroupID == id && prev.EndedAt == nil {
			st.tl = prev
			for i := range prev.Summary.MCP {
				u := prev.Summary.MCP[i]
				st.mcp[mcpKey{u.Server, u.Method, u.Name}] = &u
			}
			for i := range prev.Summary.Proxied {
				p := prev.Summary.Proxied[i]
				st.proxied[proxKey{p.Host, p.Port}] = &p
			}
			for _, b := range prev.Summary.Binaries {
				st.binaries[b] = struct{}{}
			}
			for _, n := range prev.Summary.DNSNames {
				st.names[n] = struct{}{}
			}
			for _, n := range prev.Summary.DNSBlocked {
				st.blocked[n] = struct{}{}
			}
			for _, d := range prev.Summary.UDPRefusedTo {
				ds := &destState{count: d.Count, names: make(map[string]struct{})}
				for _, n := range d.Names {
					ds.names[n] = struct{}{}
				}
				st.udpDeny[destKey{d.Proto, d.IP, d.Port}] = ds
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
	if te.CgroupID != 0 && te.CgroupID != st.tl.CgroupID && st.callFor != nil {
		if call := st.callFor(te.CgroupID); call != "" {
			te.Call = call
			cs := st.calls[call]
			if cs == nil {
				cs = &CallSummary{CallMeta: CallMeta{ID: call}, Events: map[string]int{}}
				st.calls[call] = cs
			}
			cs.Events[te.Type]++
			if strings.HasPrefix(te.Verdict, "refused") || (te.Decision == "deny" && te.Enforced) {
				cs.Refused++
			}
		}
	}
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
		if st == nil {
			return nil, nil
		}
		end := ev.Timestamp
		st.tl.EndedAt = &end
		delete(r.runs, ev.RunCgroupID)
		return r.finish(st)

	case EventExec:
		d := ev.Data.(ExecData)
		st := r.state(ev, "")
		if st == nil {
			return nil, nil
		}
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
		if st == nil {
			return nil, nil
		}
		if d.Protocol == "TCP" && r.ProxyAddrs[net.JoinHostPort(d.DstIP, strconv.Itoa(int(d.DstPort)))] {
			// To the node's proxy; what it was for arrives as http events.
			st.tl.Summary.ProxyConnects++
			return nil, nil
		}
		if d.Verdict == VerdictRedirect || d.Verdict == VerdictRefused || d.Verdict == VerdictUDP {
			// Redirected: it went to the proxy, and what it was for
			// arrives as http events. Refused: it went nowhere. Neither
			// is a destination the run reached directly.
			switch d.Verdict {
			case VerdictRedirect:
				st.tl.Summary.Redirected++
			case VerdictUDP:
				st.tl.Summary.UDPRefused++
				k := destKey{d.Protocol, d.DstIP, d.DstPort}
				ds := st.udpDeny[k]
				if ds == nil {
					ds = &destState{names: make(map[string]struct{})}
					st.udpDeny[k] = ds
				}
				ds.count++
				if n := st.ipName[d.DstIP]; n != "" {
					ds.names[n] = struct{}{}
				}
			default:
				st.tl.Summary.Refused++
			}
			st.add(TimelineEvent{Time: ev.Timestamp, Type: "connect", PID: ev.PID, CgroupID: ev.CgroupID,
				Proto: d.Protocol, DstIP: d.DstIP, DstPort: d.DstPort, DstName: st.ipName[d.DstIP], Verdict: d.Verdict}, r.MaxEvents)
			return nil, nil
		}
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
			Verdict:  d.Verdict,
		}, r.MaxEvents)

	case EventMCP:
		d := ev.Data.(MCPData)
		st := r.state(ev, "")
		if st == nil {
			return nil, nil
		}
		k := mcpKey{d.Server, d.Method, d.Name}
		u := st.mcp[k]
		if u == nil {
			u = &MCPUse{Server: d.Server, Method: d.Method, Name: d.Name}
			st.mcp[k] = u
		}
		u.Calls++
		if d.Decision == "deny" && d.Enforced {
			u.Denied++
		} else if len(d.WouldDeny) > 0 {
			u.WouldDeny++
		}
		st.add(TimelineEvent{
			Time:      ev.Timestamp,
			Type:      "mcp",
			CgroupID:  ev.CgroupID,
			Method:    d.Method,
			MCPServer: d.Server,
			MCPName:   d.Name,
			Decision:  d.Decision,
			Enforced:  d.Enforced,
			Rule:      d.Rule,
			Layer:     d.Layer,
			WouldDeny: d.WouldDeny,
			Reason:    d.Reason,
		}, r.MaxEvents)

	case EventHTTP:
		d := ev.Data.(HTTPData)
		st := r.state(ev, "")
		if st == nil {
			return nil, nil
		}
		k := proxKey{d.Host, d.Port}
		pd := st.proxied[k]
		if pd == nil {
			pd = &ProxiedDest{Host: d.Host, Port: d.Port}
			st.proxied[k] = pd
		}
		pd.addRequest(d)
		st.add(TimelineEvent{
			Time:      ev.Timestamp,
			Type:      "http",
			CgroupID:  ev.CgroupID,
			Method:    d.Method,
			DstName:   d.Host,
			DstPort:   d.Port,
			Path:      d.Path,
			Decision:  d.Decision,
			Enforced:  d.Enforced,
			Rule:      d.Rule,
			Layer:     d.Layer,
			WouldDeny: d.WouldDeny,
			Reason:    d.Reason,

			Transparent:  d.Transparent,
			OrigDst:      d.OrigDst,
			SNI:          d.SNI,
			AddrMismatch: d.AddrMismatch,
			ResolvedName: d.ResolvedName,
		}, r.MaxEvents)

	case EventExecPath:
		d := ev.Data.(ExecPathData)
		st := r.state(ev, "")
		if st == nil {
			return nil, nil
		}
		st.tl.Summary.Exec = append(st.tl.Summary.Exec, ExecUse{Path: d.Path, Trusted: d.Trusted, Verdict: d.Verdict})
		if d.Verdict != "allowed" {
			note := "untrusted path"
			if d.Trusted {
				note = "trusted path"
			}
			st.add(TimelineEvent{Time: ev.Timestamp, Type: "exec_path", PID: ev.PID, CgroupID: ev.CgroupID,
				Binary: d.Path, Verdict: d.Verdict, Note: note}, r.MaxEvents)
		}

	case EventUnix:
		d := ev.Data.(UnixData)
		st := r.state(ev, "")
		if st == nil {
			return nil, nil
		}
		st.tl.Summary.Unix = append(st.tl.Summary.Unix, UnixUse{Path: d.Path, Verdict: d.Verdict, Datagram: d.Datagram})
		st.add(TimelineEvent{Time: ev.Timestamp, Type: "unix", PID: ev.PID, CgroupID: ev.CgroupID,
			DstName: d.Path, Verdict: d.Verdict}, r.MaxEvents)

	case EventSocket:
		d := ev.Data.(SocketData)
		st := r.state(ev, "")
		if st == nil {
			return nil, nil
		}
		st.tl.Summary.SocketsRefused++
		note := fmt.Sprintf("%s %s socket", d.Op, d.Family)
		switch d.Op {
		case "create":
			note = fmt.Sprintf("create %s socket, type %d, protocol %d", d.Family, d.Type, d.Protocol)
		default:
			note += fmt.Sprintf(" created outside the run (cgroup %d)", d.SocketCgroup)
		}
		st.add(TimelineEvent{Time: ev.Timestamp, Type: "socket", PID: ev.PID, CgroupID: ev.CgroupID,
			Verdict: d.Verdict, Note: note}, r.MaxEvents)

	case EventDrop:
		d := ev.Data.(DropData)
		st := r.state(ev, "")
		if st == nil {
			return nil, nil
		}
		st.tl.Summary.Dropped += int(d.Count)
		st.add(TimelineEvent{Time: ev.Timestamp, Type: "drop", CgroupID: ev.CgroupID, Proto: d.Protocol,
			DstIP: d.DstIP, DstPort: d.DstPort, Note: fmt.Sprintf("%d packets dropped by the backstop (a lower bound: the last second before a run goes quiet is not reported)", d.Count)}, r.MaxEvents)

	case EventDNS:
		d := ev.Data.(DNSData)
		st := r.state(ev, "")
		if st == nil {
			return nil, nil
		}
		st.tl.Summary.DNSReplies++
		if d.Enforced {
			st.blocked[d.Query] = struct{}{}
		} else if d.Query != "" {
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

			Decision:  d.Decision,
			Enforced:  d.Enforced,
			Rule:      d.Rule,
			Layer:     d.Layer,
			WouldDeny: d.WouldDeny,
			Reason:    d.Reason,
			Note:      echNote(d.ECHStripped),
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
	if r.LostFor != nil {
		lost, suppressed := r.LostFor(st.tl.CgroupID)
		st.tl.LostEvents += lost
		st.tl.SuppressedEvents += suppressed
	}
	st.tl.Complete = st.sawStart && !st.gap && st.tl.LostEvents == 0 && st.tl.SuppressedEvents == 0
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
	if m.Policy != nil {
		tl.Policy = m.Policy
	}
	if len(m.Calls) > 0 {
		tl.Calls = make([]CallSummary, 0, len(m.Calls))
		for _, c := range m.Calls {
			tl.Calls = append(tl.Calls, CallSummary{CallMeta: c})
		}
	}
}

func (r *RunRecorder) write(st *runState) (*RunTimeline, error) {
	tl := st.tl
	r.mergeMeta(tl)
	// The run API's record of each call, with the counts attributed to it.
	// A call only events know of (a resumed timeline) is kept too.
	seen := map[string]bool{}
	for i := range tl.Calls {
		if cs := st.calls[tl.Calls[i].ID]; cs != nil {
			tl.Calls[i].Events, tl.Calls[i].Refused = cs.Events, cs.Refused
		}
		seen[tl.Calls[i].ID] = true
	}
	for id, cs := range st.calls {
		if !seen[id] {
			tl.Calls = append(tl.Calls, *cs)
		}
	}
	tl.Summary.Binaries = sortedKeys(st.binaries)

	tl.Summary.DNSNames = sortedKeys(st.names)
	if len(st.blocked) > 0 {
		tl.Summary.DNSBlocked = sortedKeys(st.blocked)
	}

	tl.Summary.MCP = nil
	for _, u := range st.mcp {
		tl.Summary.MCP = append(tl.Summary.MCP, *u)
	}
	sort.Slice(tl.Summary.MCP, func(i, j int) bool {
		a, b := tl.Summary.MCP[i], tl.Summary.MCP[j]
		if a.Server != b.Server {
			return a.Server < b.Server
		}
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		return a.Name < b.Name
	})

	tl.Summary.Proxied = nil
	for _, pd := range st.proxied {
		c := *pd
		c.Paths = append([]PathUse(nil), pd.Paths...)
		sort.Slice(c.Paths, func(i, j int) bool {
			if c.Paths[i].Path != c.Paths[j].Path {
				return c.Paths[i].Path < c.Paths[j].Path
			}
			return c.Paths[i].Method < c.Paths[j].Method
		})
		tl.Summary.Proxied = append(tl.Summary.Proxied, c)
	}
	sort.Slice(tl.Summary.Proxied, func(i, j int) bool {
		a, b := tl.Summary.Proxied[i], tl.Summary.Proxied[j]
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		return a.Port < b.Port
	})

	tl.Summary.Destinations = destinationList(st.dests)
	if len(st.udpDeny) > 0 {
		tl.Summary.UDPRefusedTo = destinationList(st.udpDeny)
	}

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

func echNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("ech removed from %d records", n)
}

// destinationList flattens aggregated destinations, sorted.
func destinationList(m map[destKey]*destState) []Destination {
	out := make([]Destination, 0, len(m))
	for k, ds := range m {
		d := Destination{Proto: k.proto, IP: k.ip, Port: k.port, Count: ds.count}
		if len(ds.names) > 0 {
			d.Names = sortedKeys(ds.names)
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Proto < b.Proto
	})
	return out
}

// UnixUse is a Unix socket outside the run, as first used.
type UnixUse struct {
	Path     string `json:"path"`
	Verdict  string `json:"verdict"`
	Datagram bool   `json:"datagram,omitempty"`
}

// ExecUse is a resolved exec path, as the kernel judged it.
type ExecUse struct {
	Path    string `json:"path"`
	Trusted bool   `json:"trusted"`
	Verdict string `json:"verdict"`
}
