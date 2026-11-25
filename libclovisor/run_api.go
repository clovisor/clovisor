// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// DefaultRunAPISocket is where the node agent serves the run API.
const DefaultRunAPISocket = "/run/clovisor/agent.sock"

// The run API (design §5.4). The node agent is the only process that
// creates, joins or removes run cgroups. A client:
//
//  1. connects and sends "create"; the agent creates agents/run-<id>;
//  2. starts its child parked (blocked before running any untrusted code)
//     and sends "attach" with a pidfd for it over SCM_RIGHTS; the agent
//     checks the child is the caller's and moves it into the run;
//  3. releases the child, waits for it, and sends "end" with the exit code.
//
// The run lives as long as the connection: if the client goes away
// without "end", the agent kills whatever is left and removes the cgroup.
// The exception is the node agent itself stopping: runs are then left
// alone, and whichever node agent runs next removes their cgroups once
// they empty (the reaper), so restarting the agent never kills workloads.
//
// The client cannot spawn into the cgroup itself with
// clone3(CLONE_INTO_CGROUP) unless it is root: the kernel requires write
// access to cgroup.procs of the common ancestor of the source and target
// cgroups, which for agents/ is the root cgroup.
//
// Messages are JSON, one per SOCK_SEQPACKET datagram.

const maxAPIMessage = 64 << 10

// RunAPIRequest is a client message.
type RunAPIRequest struct {
	Op       string   `json:"op"` // create, attach, end, call, call_end, profiles, clamp, revoke, mcp_register, pins, pin_approve, status, pending, ask_decide
	Command  []string `json:"command,omitempty"`
	Cwd      string   `json:"cwd,omitempty"`
	ExitCode *int     `json:"exit_code,omitempty"`
	// Profile is the profile requested for a new run. It is untrusted:
	// the ceiling chosen by the caller's credentials decides (§5.6).
	Profile string `json:"profile,omitempty"`
	// RunID and ClampProfile target clamp and revoke.
	RunID        string `json:"run_id,omitempty"`
	ClampProfile string `json:"clamp_profile,omitempty"`
	// MCPServers are stdio servers to expose through the MCP gateway
	// (op mcp_register, on the run's own connection).
	MCPServers []MCPServerSpec `json:"mcp_servers,omitempty"`
	// PinServer, PinTool and PinHash select tool pins (ops pins and
	// pin_approve). PinHash, a prefix of the pending definition's hash,
	// makes an approval apply only to the definition that was reviewed.
	PinServer string `json:"pin_server,omitempty"`
	PinTool   string `json:"pin_tool,omitempty"`
	PinHash   string `json:"pin_hash,omitempty"`
	PinsAll   bool   `json:"pins_all,omitempty"` // pins: include pins with no pending change
	// CallName labels a tool call (op call): the harness's name for it.
	CallName string `json:"call_name,omitempty"`
	// AskID, Approve and Remember decide a held request (op ask_decide);
	// AsksAll lists recently settled requests too (op pending).
	AskID    string `json:"ask_id,omitempty"`
	Approve  bool   `json:"approve,omitempty"`
	Remember bool   `json:"remember,omitempty"`
	AsksAll  bool   `json:"asks_all,omitempty"`
}

// RunAPIResponse is the agent's reply to each request.
type RunAPIResponse struct {
	OK       bool       `json:"ok"`
	Error    string     `json:"error,omitempty"`
	RunID    string     `json:"run_id,omitempty"`
	CallID   string     `json:"call_id,omitempty"` // call
	Parent   string     `json:"parent,omitempty"`  // create: the run this one is nested in
	CgroupID uint64     `json:"cgroup_id,omitempty"`
	Policy   *RunPolicy `json:"policy,omitempty"` // create, clamp, revoke
	// end: why the node agent ended the run first, if it did (a limit)
	EndReason string `json:"end_reason,omitempty"`
	Proxy     string `json:"proxy,omitempty"` // create: the node's proxy URL, if any
	// create: trust anchors for terminated destinations
	TrustBundle string `json:"trust_bundle,omitempty"`
	NodeCACert  string `json:"node_ca_cert,omitempty"`
	// profiles:
	Ceiling string   `json:"ceiling,omitempty"`
	Allow   []string `json:"allow,omitempty"`
	Default string   `json:"default,omitempty"`
	Clamp   string   `json:"clamp,omitempty"`
	// mcp_register:
	MCP []MCPRegistration `json:"mcp,omitempty"`
	// create: "cgroup", or "credential" when the proxy knows the run by the
	// secret in Proxy and the client starts the run's process itself.
	Identity string `json:"identity,omitempty"`
	// pins, pin_approve:
	Pins     []PinEntry `json:"pins,omitempty"`
	Approved []string   `json:"approved,omitempty"`
	// status:
	Status *NodeStatus `json:"status,omitempty"`
	// pending, ask_decide:
	Asks []PendingAsk `json:"asks,omitempty"`
}

// RunRegistry holds metadata for runs created through the API until the
// recorder has written their timelines. Safe for concurrent use.
type RunRegistry struct {
	mu    sync.Mutex
	m     map[string]RunMeta
	calls map[uint64]string // call cgroup id -> call id
	// Nested runs (milestone 4.6): their cgroups and their calls' map to
	// the nested run's cgroup, which kernel events (keyed by the top-level
	// run) are recorded under instead.
	nestedCg map[string]uint64
	nested   map[uint64]uint64
}

// NewRunRegistry returns an empty registry.
func NewRunRegistry() *RunRegistry {
	return &RunRegistry{m: map[string]RunMeta{}, calls: map[uint64]string{},
		nestedCg: map[string]uint64{}, nested: map[uint64]uint64{}}
}

// AddCall records a tool call (or MCP server) of a known run.
func (r *RunRegistry) AddCall(runID string, c CallMeta) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if m, ok := r.m[runID]; ok {
		m.Calls = append(append([]CallMeta{}, m.Calls...), c)
		r.m[runID] = m
		r.calls[c.CgroupID] = c.ID
		if ncg := r.nestedCg[runID]; ncg != 0 {
			r.nested[c.CgroupID] = ncg
		}
	}
}

// IndexCall attributes a restored run's open call's cgroup to it again
// (milestone 6.1); the call is already in the run's record.
func (r *RunRegistry) IndexCall(runID string, c CallMeta) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[c.CgroupID] = c.ID
	if ncg := r.nestedCg[runID]; ncg != 0 {
		r.nested[c.CgroupID] = ncg
	}
}

// PutNested records a nested run, started from inside parent, whose
// cgroup is cg; the parent's record lists it as a child.
func (r *RunRegistry) PutNested(m RunMeta, cg uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[m.RunID] = m
	r.nestedCg[m.RunID] = cg
	r.nested[cg] = cg
	if p, ok := r.m[m.Parent]; ok {
		p.Children = append(append([]string{}, p.Children...), m.RunID)
		r.m[m.Parent] = p
	}
}

// NestedRunFor returns the cgroup of the nested run cgroupID is in (the
// nested run's own cgroup or one of its calls'), or 0.
func (r *RunRegistry) NestedRunFor(cgroupID uint64) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.nested[cgroupID]
}

// EndCall records how a call ended.
func (r *RunRegistry) EndCall(runID, callID string, exitCode *int) {
	end := time.Now().UTC()
	r.Update(runID, func(m *RunMeta) {
		calls := append([]CallMeta{}, m.Calls...)
		for i := range calls {
			if calls[i].ID == callID && calls[i].EndedAt == nil {
				calls[i].EndedAt, calls[i].ExitCode = &end, exitCode
			}
		}
		m.Calls = calls
	})
}

// CallFor names the call whose cgroup is cgroupID, or "".
func (r *RunRegistry) CallFor(cgroupID uint64) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[cgroupID]
}

// Put records metadata for a run.
func (r *RunRegistry) Put(m RunMeta) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[m.RunID] = m
}

// Update changes the metadata of a known run.
func (r *RunRegistry) Update(runID string, f func(*RunMeta)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if m, ok := r.m[runID]; ok {
		f(&m)
		r.m[runID] = m
	}
}

// Get returns the metadata for a run.
func (r *RunRegistry) Get(runID string) (RunMeta, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.m[runID]
	return m, ok
}

// Done forgets a run whose timeline has been written.
func (r *RunRegistry) Done(runID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.m[runID].Calls {
		delete(r.calls, c.CgroupID)
		delete(r.nested, c.CgroupID)
	}
	if cg := r.nestedCg[runID]; cg != 0 {
		delete(r.nested, cg)
		delete(r.nestedCg, runID)
	}
	delete(r.m, runID)
}

// RunAPIServer serves the run API on a unix socket.
type RunAPIServer struct {
	cm        *CgroupManager
	reg       *RunRegistry
	agentsRel string // agents dir relative to the cgroup root, e.g. /agents
	ln        *net.UnixListener
	path      string

	policy atomic.Pointer[policy.Set] // nil: no policy loaded; runs are unprofiled
	// ProxyURL is the node's explicit proxy, handed to clients for runs.
	ProxyURL string
	// Transparent is the node's transparent mode. In enforce, a process
	// holding network sockets is refused at attach: the kernel runs a
	// socket's cgroup hooks by the cgroup it was created in, so those
	// sockets would bypass redirect-or-deny (3.0 spike).
	Transparent string
	// Status reports the node's enforcement state (agentctl status).
	Status func() NodeStatus
	// OnPolicy, if set, hears a run's effective policy whenever it is
	// bound or clamped, so kernel state can follow (milestone 4.2). For a
	// nested run it also marks the cgroup, so the kernel looks its policy
	// up by it (milestone 4.6); a nested run is refused if that fails.
	OnPolicy func(runCg uint64, uid int, eff *policy.Effective, nested bool) error
	// OnNestedEnd, if set, hears that a nested run's cgroup is gone.
	OnNestedEnd func(runCg uint64)
	// OnRunStart, if set, hears of every run once its cgroup exists and
	// before any process joins it; OnRunEnd as it ends, before its cgroup
	// is removed, while its metadata can still change (milestone 5.2).
	OnRunStart func(runID string, runCg uint64)
	OnRunEnd   func(runID string, runCg uint64)
	// MCP is the local MCP gateway, if enabled.
	MCP *MCPGateway
	// Pins is the node's tool-definition pin store, if MCP is governed.
	Pins *PinStore
	// Asks is the queue of requests held for a person (milestone 5.5).
	Asks *AskQueue
	// TrustBundle and NodeCACert are handed to runs when the proxy
	// terminates TLS.
	TrustBundle, NodeCACert string
	// Events receives run start and end with credential identity, where
	// no cgroup mkdir or rmdir reports them.
	Events chan<- AuditEvent
	// GrantsPath is where live runs' grants are kept across node agent
	// restarts (milestone 6.1); "" keeps none.
	GrantsPath string
	grantMu    sync.Mutex

	nextCg uint64            // credential identity: synthetic run ids
	tokens map[string]string // credential identity: token -> run id
	tokOf  map[string]string // run id -> token
	// Tool calls (milestone 4.5), per run: the last call number given, and
	// how many are open.
	callSeq   map[string]int
	liveCalls map[string]int
	// Nested runs (milestone 4.6): each live nested run's parent, and
	// each live run's live children.
	parentOf map[string]string
	children map[string][]string
	// endReasons holds why the node agent ended a run, until its client
	// ends it too and is told (the run's metadata may be gone by then).
	endReasons map[string]string

	mu      sync.Mutex
	conns   map[*net.UnixConn]struct{}
	active  map[string]bool // runs owned by a live connection
	bound   map[string]*boundRun
	byCg    map[uint64]*boundRun
	runByCg map[uint64]string // every live run, profiled or not, and its child cgroups
	runCg   map[string]uint64 // run id -> the run's own cgroup id
	// restored are runs given back their grants at start that no
	// connection owns yet, with when the reaper first found them empty;
	// creators, every live run's agentctl, which may claim one.
	restored map[string]time.Time
	creators map[string]procIdentity
	closing  bool
	done     chan struct{}
	wg       sync.WaitGroup
}

// boundRun is a live run's effective policy.
type boundRun struct {
	runID    string
	uid      int
	cgroupID uint64
	eff      *policy.Effective // replaced, never mutated, under RunAPIServer.mu
	started  time.Time
}

// ownerOf is the uid a live run belongs to, or -1.
func (s *RunAPIServer) ownerOf(runID string) int {
	s.mu.Lock()
	b := s.bound[runID]
	s.mu.Unlock()
	if b != nil {
		return b.uid
	}
	if s.reg != nil {
		if m, ok := s.reg.Get(runID); ok {
			return m.UID
		}
	}
	return -1
}

// runLink is one run in a chain of nested runs.
type runLink struct {
	runID    string
	cgroupID uint64
	eff      *policy.Effective // nil: unprofiled
	started  time.Time
}

// chain is runID and the runs it is nested in, outermost first. Empty if
// runID is not live.
func (s *RunAPIServer) chain(runID string) []runLink {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []runLink
	for r := runID; r != ""; r = s.parentOf[r] {
		if !s.active[r] {
			return nil
		}
		l := runLink{runID: r, cgroupID: s.runCg[r]}
		if b := s.bound[r]; b != nil {
			l.eff, l.started = b.eff, b.started
		}
		out = append([]runLink{l}, out...)
		if len(out) > maxNest+1 {
			break
		}
	}
	return out
}

// liveRuns lists the live runs.
func (s *RunAPIServer) liveRuns() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.active))
	for r := range s.active {
		out = append(out, r)
	}
	return out
}

// EndRunFor ends a live run, and its nested runs, recording why: the node
// agent's own decision (a duration limit), not its client's.
func (s *RunAPIServer) EndRunFor(runID, reason string) {
	why := map[string]string{runID: reason}
	for _, k := range s.descendantsOf(runID) {
		why[k] = "its parent run " + runID + " ended: " + reason
	}
	s.mu.Lock()
	if s.endReasons == nil {
		s.endReasons = map[string]string{}
	}
	for r, w := range why {
		s.endReasons[r] = w
	}
	s.mu.Unlock()
	for r, w := range why {
		s.reg.Update(r, func(m *RunMeta) { m.EndReason = w })
	}
	log.Printf("run api: run %s: ending it: %s", runID, reason)
	s.endRun(runID, nil)
}

func (s *RunAPIServer) descendantsOf(runID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.descendants(runID)
}

// SetPolicy installs the policy used for new runs. Runs already bound
// keep the versions they were bound to (§5.6, versioned binding).
func (s *RunAPIServer) SetPolicy(set *policy.Set) { s.policy.Store(set) }

// effectiveOf returns a live run's current effective policy, or nil.
func (s *RunAPIServer) effectiveOf(runID string) *policy.Effective {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.bound[runID]; ok {
		return b.eff
	}
	return nil
}

// addRunCgroup attributes a child cgroup of a run (an MCP server's) to
// the run, so enforcement points identify its sockets as the run's.
func (s *RunAPIServer) addRunCgroup(runID string, cgroupID uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active[runID] {
		return
	}
	s.runByCg[cgroupID] = runID
	if b, ok := s.bound[runID]; ok {
		s.byCg[cgroupID] = b
	}
}

// RunFor returns the live run that cgroupID belongs to (the run's own
// cgroup or one of its children), the run's own cgroup id, under which its
// events are recorded, and its effective policy (nil for an unprofiled run).
func (s *RunAPIServer) RunFor(cgroupID uint64) (runID string, runCg uint64, eff *policy.Effective, isRun bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	runID, isRun = s.runByCg[cgroupID]
	if b, ok := s.byCg[cgroupID]; ok {
		eff = b.eff
	}
	return runID, s.runCg[runID], eff, isRun
}

// reapInterval is how often orphaned run cgroups are checked.
const reapInterval = 5 * time.Second

// CredentialRunsDir is the virtual agents directory under which runs
// with credential identity are recorded: they have no cgroup.
const CredentialRunsDir = "/clovisor-credential-runs"

// credentialCgBase marks synthetic run ids, which no cgroup id reaches.
const credentialCgBase = uint64(1) << 62

// NewRunAPIServer listens on path. The socket is world-connectable:
// every request is checked against the caller's kernel credentials, and
// a caller can only ever confine its own children.
//
// With cm nil, runs have credential identity (design §4.3): no cgroup,
// and the proxy knows a run by the secret in its proxy URL. That is a
// claim, not an enforcement-grade identity: any process holding the
// secret speaks for the run, and one that does not use the proxy is not
// governed at all.
func NewRunAPIServer(path string, cm *CgroupManager, reg *RunRegistry) (*RunAPIServer, error) {
	rel := ""
	if cm != nil {
		r, err := filepath.Rel(CgroupV2Root, cm.GetAgentsDir())
		if err != nil {
			return nil, err
		}
		rel = "/" + r
	}
	// The directory must be traversable by everyone; it may predate us
	// with a tighter mode, which MkdirAll would leave alone.
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	ln, err := net.ListenUnix(apiNet, &net.UnixAddr{Name: path, Net: apiNet})
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		ln.Close()
		return nil, err
	}
	return &RunAPIServer{
		cm:         cm,
		reg:        reg,
		agentsRel:  rel,
		ln:         ln,
		path:       path,
		conns:      map[*net.UnixConn]struct{}{},
		active:     map[string]bool{},
		bound:      map[string]*boundRun{},
		byCg:       map[uint64]*boundRun{},
		runByCg:    map[uint64]string{},
		runCg:      map[string]uint64{},
		tokens:     map[string]string{},
		tokOf:      map[string]string{},
		callSeq:    map[string]int{},
		liveCalls:  map[string]int{},
		parentOf:   map[string]string{},
		children:   map[string][]string{},
		endReasons: map[string]string{},
		restored:   map[string]time.Time{},
		creators:   map[string]procIdentity{},
		nextCg:     credentialCgBase,
		done:       make(chan struct{}),
	}, nil
}

// reap removes run cgroups that no connection owns once they are empty:
// runs left behind by an earlier node agent, or by a client whose end
// failed. Removing the cgroup is what finalizes the run's timeline.
func (s *RunAPIServer) reap() {
	if s.cm == nil {
		return
	}
	s.endUnclaimed()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, cg := range s.cm.ListActiveCgroups() {
		if s.active[cg.RunID] {
			continue
		}
		if populated, err := cgroupPopulated(cg.Path); err != nil || populated {
			continue
		}
		if err := removeCgroupTree(cg.Path); err != nil {
			log.Printf("run api: reap %s: %v", cg.Path, err)
			continue
		}
		log.Printf("run api: removed orphaned run cgroup %s", cg.Path)
	}
}

// restoredGrace is how long a restored run's cgroup must stay empty
// before the reaper ends it: long enough for its agentctl, whose child
// has just exited, to report the exit code itself.
const restoredGrace = 10 * time.Second

// endUnclaimed ends restored runs no agentctl has claimed once their
// cgroups have been empty for restoredGrace.
func (s *RunAPIServer) endUnclaimed() {
	var done []string
	now := time.Now()
	s.mu.Lock()
	for runID, empty := range s.restored {
		path, ok := s.cm.GetRunCgroupPath(runID)
		if !ok {
			continue
		}
		if populated, err := cgroupPopulated(path); err != nil || populated {
			s.restored[runID] = time.Time{}
			continue
		}
		if empty.IsZero() {
			s.restored[runID] = now
			continue
		}
		if now.Sub(empty) >= restoredGrace {
			done = append(done, runID)
		}
	}
	s.mu.Unlock()
	for _, r := range done {
		log.Printf("run api: restored run %s is empty and no client reported its end; ending it", r)
		s.endRun(r, nil)
	}
}

func (s *RunAPIServer) reapLoop() {
	defer s.wg.Done()
	t := time.NewTicker(reapInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.reap()
		case <-s.done:
			return
		}
	}
}

// Serve accepts connections until Close.
func (s *RunAPIServer) Serve() {
	s.reap()
	s.wg.Add(1)
	go s.reapLoop()
	for {
		c, err := s.ln.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("run api: accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(c)
			s.mu.Lock()
			delete(s.conns, c)
			s.mu.Unlock()
		}()
	}
}

// Close stops accepting and disconnects clients, leaving their runs in
// place, and waits for handlers.
func (s *RunAPIServer) Close() {
	s.ln.Close()
	s.mu.Lock()
	s.closing = true
	close(s.done)
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	os.Remove(s.path)
}

// CredentialIdentity reports whether runs are known by proxy credential
// rather than by cgroup.
func (s *RunAPIServer) CredentialIdentity() bool { return s.cm == nil }

// RunForCredential returns the live run a proxy credential (user
// run-<id>, password the run's token) names.
func (s *RunAPIServer) RunForCredential(user, token string) (runID string, runCg uint64, eff *policy.Effective, ok bool) {
	if token == "" {
		return "", 0, nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id, found := s.tokens[token]
	if !found || subtle.ConstantTimeCompare([]byte(user), []byte(RunPrefix+id)) != 1 {
		return "", 0, nil, false
	}
	cg := s.runCg[id]
	if b, ok := s.byCg[cg]; ok {
		eff = b.eff
	}
	return id, cg, eff, true
}

// TokenFor returns a live run's credential token.
func (s *RunAPIServer) TokenFor(runID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokOf[runID]
}

// emit sends a run lifecycle event to the recorder. It blocks rather
// than drop: a lost start or end would lose the run's timeline.
func (s *RunAPIServer) emit(typ int, runID string, cg uint64) {
	if s.Events == nil {
		return
	}
	s.Events <- AuditEvent{Type: typ, Timestamp: time.Now(), CgroupID: cg, RunCgroupID: cg,
		Data: RunData{CgroupPath: CredentialRunsDir + "/" + RunPrefix + runID}}
}

func (s *RunAPIServer) inAgents(cg string) bool {
	if s.agentsRel == "" {
		return false
	}
	return cg == s.agentsRel || strings.HasPrefix(cg, s.agentsRel+"/")
}

type apiConn struct {
	s        *RunAPIServer
	c        *net.UnixConn
	cred     *peerInfo
	runID    string
	runPath  string
	cgID     uint64
	cwd      string
	attached bool
	// parent is the run this connection's run is nested in, if any: its
	// process must come from inside that run.
	parent string

	// A tool call (op call) instead of a run: the caller is inside the run.
	callID   string
	callRun  string
	callPath string
	callDone bool
}

func (s *RunAPIServer) handle(c *net.UnixConn) {
	defer c.Close()
	cred, err := peerCred(c)
	if err != nil {
		log.Printf("run api: peer credentials: %v", err)
		return
	}
	ac := &apiConn{s: s, c: c, cred: cred}
	defer ac.abandon()

	mc := newMsgConn(c)
	for {
		msg, fds, err := mc.recv()
		if err != nil && !errors.Is(err, errMsgTooLarge) {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("run api: read: %v", err)
			}
			return
		}
		var resp RunAPIResponse
		var req RunAPIRequest
		switch {
		case err != nil:
			resp.Error = "message too large"
		default:
			if err := json.Unmarshal(msg, &req); err != nil {
				resp.Error = "bad request: " + err.Error()
			} else {
				resp = ac.dispatch(req, fds)
				fds = nil // dispatch owns them
			}
		}
		closeFDs(fds)
		out, _ := json.Marshal(resp)
		if err := mc.send(out); err != nil {
			return
		}
		if (req.Op == "end" || req.Op == "call_end") && resp.OK {
			return
		}
	}
}

func fail(format string, a ...interface{}) RunAPIResponse {
	return RunAPIResponse{Error: fmt.Sprintf(format, a...)}
}

func (ac *apiConn) dispatch(req RunAPIRequest, fds []int) RunAPIResponse {
	defer closeFDs(fds)
	switch req.Op {
	case "create":
		return ac.create(req)
	case "attach":
		if ac.s.cm == nil {
			return fail("runs have credential identity here: there is no cgroup to attach to, start the process with the run's proxy settings")
		}
		if len(fds) != 1 {
			return fail("attach needs exactly one pidfd, got %d fds", len(fds))
		}
		if ac.callID != "" {
			return ac.attachCall(fds[0])
		}
		return ac.attach(fds[0])
	case "end":
		if ac.callID != "" {
			return fail("this connection holds a call: send call_end")
		}
		if ac.runID == "" && req.RunID != "" {
			if err := ac.claim(strings.TrimPrefix(req.RunID, RunPrefix)); err != nil {
				return fail("%v", err)
			}
		}
		return ac.end(req.ExitCode)
	case "call":
		return ac.call(req)
	case "call_end":
		return ac.callEnd(req.ExitCode)
	case "profiles":
		return ac.profiles()
	case "clamp", "revoke":
		return ac.clamp(req)
	case "mcp_register":
		return ac.mcpRegister(req)
	case "pins", "pin_approve":
		return ac.pins(req)
	case "pending", "ask_decide":
		return ac.asks(req)
	case "status":
		if ac.s.Status == nil {
			return fail("status unavailable")
		}
		st := ac.s.Status()
		return RunAPIResponse{OK: true, Status: &st}
	default:
		return fail("unknown op %q", req.Op)
	}
}

func (ac *apiConn) create(req RunAPIRequest) RunAPIResponse {
	if ac.runID != "" {
		return fail("this connection already has run %s", ac.runID)
	}
	if len(req.Command) == 0 {
		return fail("command required")
	}
	// A run started from inside a run is nested in it (design §7.8,
	// milestone 4.6): its cgroup is below the parent's and its effective
	// policy is the parent's plus its own, so it can never have more.
	// With credential identity there is no cgroup to check, so a run can
	// start another run within its user's ceiling, escaping its own
	// clamps; the receipt says identity is a claim there.
	var parent string
	var parentEff *policy.Effective
	var parentRP *RunPolicy
	if ac.s.cm != nil {
		cg, err := procCgroup(int(ac.cred.Pid))
		if err != nil {
			return fail("cannot read caller's cgroup: %v", err)
		}
		if ac.s.inAgents(cg) {
			parent = ac.s.runOfCgroupPath(cg)
			if parent == "" {
				return fail("caller is inside the agents cgroup but not in a run (%s)", cg)
			}
			if d := ac.s.runDepth(cg) + 1; d > maxNest {
				return fail("a run in run %s would be nested %d deep; runs nest at most %d deep", parent, d, maxNest)
			}
			ac.s.mu.Lock()
			live := ac.s.active[parent]
			if b := ac.s.bound[parent]; b != nil {
				parentEff = b.eff
			}
			ac.s.mu.Unlock()
			pm, ok := ac.s.reg.Get(parent)
			switch {
			case !live || !ok:
				return fail("run %s is not live", parent)
			case pm.UID != int(ac.cred.Uid):
				return fail("run %s belongs to another user", parent)
			}
			parentRP = pm.Policy
		}
	}

	// Bind the profile before the cgroup exists, so that no process ever
	// runs in it without its policy (§5.6).
	var binding *policy.Binding
	if set := ac.s.policy.Load(); set != nil {
		caller, err := ac.caller()
		if err != nil {
			return fail("%v", err)
		}
		binding, err = set.Resolve(caller, req.Profile)
		if errors.Is(err, policy.ErrNoCeiling) {
			binding, err = nil, nil // unprofiled: audit only, as in Phase 1
		}
		if err != nil {
			return fail("%v", err)
		}
	} else if req.Profile != "" {
		return fail("the node agent has no policy loaded, so it cannot grant profile %q", req.Profile)
	}
	var eff *policy.Effective
	if binding != nil {
		eff = binding.Effective
	}
	if parent != "" {
		eff = policy.Nested(parentEff, eff)
		if eff != nil && len(eff.ExecLayers()) > maxKernelExecLayers {
			return fail("run %s and the profile requested have %d exec layers between them; the kernel holds %d",
				parent, len(eff.ExecLayers()), maxKernelExecLayers)
		}
	}

	runID, err := NewRunID()
	if err != nil {
		return fail("%v", err)
	}
	ac.s.mu.Lock()
	var path, token string
	var id uint64
	switch {
	case parent != "" && !ac.s.active[parent]:
		err = fmt.Errorf("run %s ended", parent) // while this one was being bound
	case parent != "":
		path, id, err = ac.s.cm.CreateNestedRunCgroup(parent, runID)
	case ac.s.cm != nil:
		path, id, err = ac.s.cm.CreateRunCgroup(runID)
	default:
		ac.s.nextCg++
		id = ac.s.nextCg
		var t [16]byte
		if _, err = rand.Read(t[:]); err == nil {
			token = hex.EncodeToString(t[:])
			ac.s.tokens[token] = runID
			ac.s.tokOf[runID] = token
		}
	}
	if err == nil {
		ac.s.active[runID] = true
		ac.s.creators[runID] = procIdentityOf(ac.cred.Pid)
		ac.s.runByCg[id] = runID
		ac.s.runCg[runID] = id
		if eff != nil {
			b := &boundRun{runID: runID, uid: int(ac.cred.Uid), cgroupID: id, eff: eff, started: time.Now()}
			ac.s.bound[runID] = b
			ac.s.byCg[id] = b
		}
		if parent != "" {
			ac.s.parentOf[runID] = parent
			ac.s.children[parent] = append(ac.s.children[parent], runID)
		}
	}
	ac.s.mu.Unlock()
	if err != nil {
		return fail("%v", err)
	}
	ac.runID, ac.runPath, ac.cgID, ac.cwd, ac.parent = runID, path, id, req.Cwd, parent
	if ac.s.OnRunStart != nil {
		ac.s.OnRunStart(runID, id)
	}
	if eff != nil && ac.s.OnPolicy != nil {
		if err := ac.s.OnPolicy(id, int(ac.cred.Uid), eff, parent != ""); err != nil && parent != "" {
			// The kernel would look the nested run's policy up by its
			// parent's: refuse rather than run it with more.
			ac.finish(nil)
			return fail("cannot give nested run its kernel policy: %v", err)
		}
	}
	rp := runPolicyRecord(binding)
	if parent != "" {
		rp = nestedPolicyRecord(parent, parentRP, binding, eff)
	}
	meta := RunMeta{
		RunID:     runID,
		Command:   req.Command,
		Cwd:       req.Cwd,
		UID:       int(ac.cred.Uid),
		StartedAt: time.Now().UTC(),
		Policy:    rp,
		Parent:    parent,
	}
	if parent != "" {
		ac.s.reg.PutNested(meta, id)
	} else {
		ac.s.reg.Put(meta)
	}
	ac.s.saveGrants()
	if ac.s.cm == nil {
		ac.s.emit(EventRunStart, runID, id)
	}
	granted := "unprofiled"
	if binding != nil {
		g := binding.Effective.Layers[0]
		granted = g.Profile.Name + "@" + g.Profile.Profile.ShortVersion() + " (" + binding.Reason + ")"
	}
	if parent != "" {
		granted += ", nested in run " + parent
	}
	log.Printf("run api: run %s created for uid %d pid %d: %s", runID, ac.cred.Uid, ac.cred.Pid, granted)
	resp := RunAPIResponse{OK: true, RunID: runID, CgroupID: id, Policy: rp, Proxy: ac.s.ProxyURL,
		TrustBundle: ac.s.TrustBundle, NodeCACert: ac.s.NodeCACert, Identity: "cgroup", Parent: parent}
	if ac.s.cm == nil {
		resp.CgroupID, resp.Identity = 0, "credential"
		if u, err := url.Parse(ac.s.ProxyURL); err == nil && ac.s.ProxyURL != "" {
			u.User = url.UserPassword(RunPrefix+runID, token)
			resp.Proxy = u.String()
		}
	}
	return resp
}

// caller is the requester's platform identity: uid from SO_PEERCRED,
// groups from the kernel's view of the requesting process.
func (ac *apiConn) caller() (policy.Caller, error) {
	c := policy.Caller{UID: int(ac.cred.Uid), GIDs: []int{int(ac.cred.Gid)}}
	groups, err := ac.cred.groups()
	if err != nil {
		return c, fmt.Errorf("cannot read caller's groups: %v", err)
	}
	c.GIDs = append(c.GIDs, groups...)
	return c, nil
}

func layerRecord(l policy.Layer, at time.Time) PolicyLayer {
	return PolicyLayer{
		Profile: l.Profile.Name,
		Version: l.Profile.Profile.ShortVersion(),
		Mode:    l.Profile.Mode,
		Source:  l.Source,
		At:      at,
		Observe: l.Profile.CapturesTLS(),
	}
}

// nestedPolicyRecord is a nested run's record: its parent's layers as
// they stand, marked inherited, then the layers of its own binding that
// the parent did not already have. The chain of runs is the receipt.
func nestedPolicyRecord(parent string, prp *RunPolicy, b *policy.Binding, eff *policy.Effective) *RunPolicy {
	if eff == nil {
		return nil
	}
	rp := &RunPolicy{Parent: parent}
	if b != nil {
		rp.Requested, rp.Ceiling, rp.Reason = b.Requested, b.Ceiling, b.Reason
	} else {
		rp.Reason = "no ceiling covers the caller; bound by its parent only"
	}
	n := 0
	if prp != nil {
		for _, l := range prp.Layers {
			l.Source = "run " + parent + ": " + l.Source
			rp.Layers = append(rp.Layers, l)
		}
		n = len(prp.Layers)
	}
	now := time.Now().UTC()
	// eff's layers past the parent's are this run's own.
	if n > len(eff.Layers) {
		n = len(eff.Layers)
	}
	for _, l := range eff.Layers[n:] {
		rp.Layers = append(rp.Layers, layerRecord(l, now))
	}
	return rp
}

func runPolicyRecord(b *policy.Binding) *RunPolicy {
	if b == nil {
		return nil
	}
	now := time.Now().UTC()
	rp := &RunPolicy{Requested: b.Requested, Ceiling: b.Ceiling, Reason: b.Reason}
	for _, l := range b.Effective.Layers {
		rp.Layers = append(rp.Layers, layerRecord(l, now))
	}
	return rp
}

func (ac *apiConn) profiles() RunAPIResponse {
	set := ac.s.policy.Load()
	if set == nil {
		return fail("the node agent has no policy loaded")
	}
	caller, err := ac.caller()
	if err != nil {
		return fail("%v", err)
	}
	name, allow, def, clamp, err := set.Allowed(caller)
	if err != nil {
		return fail("%v", err)
	}
	return RunAPIResponse{OK: true, Ceiling: name, Allow: allow, Default: def, Clamp: clamp}
}

// mcpRegister exposes the run's stdio MCP servers through the gateway.
// Only the connection that created the run may do it.
func (ac *apiConn) mcpRegister(req RunAPIRequest) RunAPIResponse {
	if ac.runID == "" {
		return fail("no run: send create first")
	}
	if ac.s.MCP == nil {
		return fail("this node agent has no MCP gateway (start it with -mcp-listen)")
	}
	caller, err := ac.caller()
	if err != nil {
		return fail("%v", err)
	}
	run := &mcpRun{runID: ac.runID, cgPath: ac.runPath, cgID: ac.cgID, uid: int(ac.cred.Uid),
		gid: int(ac.cred.Gid), groups: caller.GIDs[1:], cwd: ac.cwd}
	return RunAPIResponse{OK: true, RunID: ac.runID, MCP: ac.s.MCP.Register(run, req.MCPServers)}
}

// pins lists tool pins, or approves changed definitions. Pins are node
// state that governs every run, so only root outside any run may touch
// them.
func (ac *apiConn) pins(req RunAPIRequest) RunAPIResponse {
	if ac.cred.Uid != 0 {
		return fail("tool pins are node state: run as root")
	}
	if ac.s.cm != nil {
		if cg, err := procCgroup(int(ac.cred.Pid)); err != nil || ac.s.inAgents(cg) {
			return fail("tool pins cannot be reviewed from inside a run")
		}
	}
	if ac.s.Pins == nil {
		return fail("the node agent has no MCP pin store (no proxy and no MCP gateway)")
	}
	if req.Op == "pin_approve" {
		if req.PinServer == "" {
			return fail("pin_approve needs a server")
		}
		done, err := ac.s.Pins.Approve(req.PinServer, req.PinTool, req.PinHash)
		if len(done) > 0 {
			log.Printf("run api: uid %d approved tool definitions %s on %s", ac.cred.Uid, strings.Join(done, ", "), req.PinServer)
		}
		if err != nil {
			return RunAPIResponse{Error: err.Error(), Approved: done}
		}
		if len(done) == 0 {
			return fail("no changed tool definitions to approve on %s", req.PinServer)
		}
		return RunAPIResponse{OK: true, Approved: done}
	}
	var out []PinEntry
	for _, e := range ac.s.Pins.List(!req.PinsAll && req.PinTool == "") {
		if req.PinServer != "" && e.Server != req.PinServer || req.PinTool != "" && e.Tool != req.PinTool {
			continue
		}
		if req.PinTool == "" {
			// Definitions only for one tool: a listing must fit a message.
			e.Pin.Def = nil
			if e.Pin.Pending != nil {
				e.Pin.Pending.Def = nil
			}
		}
		out = append(out, e)
	}
	resp := RunAPIResponse{OK: true, Pins: out}
	if b, _ := json.Marshal(resp); len(b) > maxAPIMessage-256 {
		return fail("the answer is too large for the run API; read %s as root", ac.s.Pins.path)
	}
	return resp
}

// clamp layers a profile onto a live run, or revokes its egress. A layer
// can only remove permissions, so the run's owner may do it as well as
// root: it is the incident-response lever of §5.6.
func (ac *apiConn) clamp(req RunAPIRequest) RunAPIResponse {
	runID := strings.TrimPrefix(req.RunID, RunPrefix)
	var layer policy.Layer
	who := fmt.Sprintf("uid %d", ac.cred.Uid)
	if req.Op == "revoke" {
		layer = policy.Layer{Profile: policy.RevokedProfile(), Source: "revoked by " + who}
	} else {
		set := ac.s.policy.Load()
		if set == nil {
			return fail("the node agent has no policy loaded")
		}
		cp := set.Profile(req.ClampProfile)
		if cp == nil {
			return fail("no profile named %q", req.ClampProfile)
		}
		layer = policy.Layer{Profile: cp, Source: "clamped by " + who}
	}

	// From inside a run, only that run and the runs nested in it: a
	// sub-agent must not be able to revoke its parent or its siblings.
	var within string
	if ac.s.cm != nil {
		if cg, err := procCgroup(int(ac.cred.Pid)); err != nil {
			return fail("cannot read caller's cgroup: %v", err)
		} else if ac.s.inAgents(cg) {
			if within = ac.s.runOfCgroupPath(cg); within == "" {
				return fail("caller is inside the agents cgroup but not in a run")
			}
		}
	}

	rp, err := ac.s.applyLayer(runID, layer, func(b *boundRun) string {
		if ac.cred.Uid != 0 && int(ac.cred.Uid) != b.uid {
			return fmt.Sprintf("run %s belongs to another user", runID)
		}
		if within != "" && within != runID && !contains(ac.s.descendants(within), runID) {
			return fmt.Sprintf("from inside run %s, only it and the runs nested in it can be clamped", within)
		}
		return ""
	})
	if err != nil {
		return fail("%v", err)
	}
	return RunAPIResponse{OK: true, RunID: runID, Policy: rp}
}

// applyLayer layers a profile onto a live run and the runs nested in it,
// in the proxy, the kernel and the run's record. permit, called with the
// lock held, may refuse.
func (s *RunAPIServer) applyLayer(runID string, layer policy.Layer, permit func(*boundRun) string) (*RunPolicy, error) {
	type update struct {
		b   *boundRun
		eff *policy.Effective
	}
	var updates []update
	s.mu.Lock()
	b, ok := s.bound[runID]
	if ok && permit != nil {
		if why := permit(b); why != "" {
			s.mu.Unlock()
			return nil, errors.New(why)
		}
	}
	var kids []string
	if ok {
		// The clamp cascades: a nested run's policy is its parent's and
		// more, so it must stay at most its parent's (§7.8).
		kids = s.descendants(runID)
		for _, r := range append([]string{runID}, kids...) {
			if bb := s.bound[r]; bb != nil {
				bb.eff = bb.eff.With(layer)
				updates = append(updates, update{bb, bb.eff})
			}
		}
	}
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no live profiled run %s", runID)
	}
	if s.OnPolicy != nil {
		for _, u := range updates {
			if err := s.OnPolicy(u.b.cgroupID, u.b.uid, u.eff, s.isNested(u.b.runID)); err != nil {
				log.Printf("run api: run %s: kernel policy after %s: %v", u.b.runID, layer.Source, err)
			}
		}
	}

	at := time.Now().UTC()
	var rp *RunPolicy
	for _, r := range append([]string{runID}, kids...) {
		lr := layerRecord(layer, at)
		if r != runID {
			lr.Source = "run " + runID + ": " + lr.Source
		}
		s.reg.Update(r, func(m *RunMeta) {
			if m.Policy != nil {
				// Copy on write: the recorder may hold the old record.
				np := *m.Policy
				np.Layers = append(append([]PolicyLayer{}, m.Policy.Layers...), lr)
				m.Policy = &np
				if r == runID {
					rp = &np
				}
			}
		})
	}
	s.saveGrants()
	if len(kids) > 0 {
		log.Printf("run api: run %s: %s %s, and its nested runs %s", runID, layer.Source, layer.Profile.Name, strings.Join(kids, ", "))
	} else {
		log.Printf("run api: run %s: %s %s", runID, layer.Source, layer.Profile.Name)
	}
	return rp, nil
}

func (ac *apiConn) end(exitCode *int) RunAPIResponse {
	if ac.runID == "" {
		return fail("no run")
	}
	runID := ac.runID
	ac.finish(exitCode)
	ac.s.mu.Lock()
	why := ac.s.endReasons[runID]
	delete(ac.s.endReasons, runID)
	ac.s.mu.Unlock()
	return RunAPIResponse{OK: true, RunID: runID, EndReason: why}
}

// claim makes a run restored at start (milestone 6.1) this connection's,
// for its agentctl to report its end after the node agent restarted.
// Only the process that created it may: the same pid and start time.
func (ac *apiConn) claim(runID string) error {
	me := procIdentityOf(ac.cred.Pid)
	ac.s.mu.Lock()
	defer ac.s.mu.Unlock()
	if _, ok := ac.s.restored[runID]; !ok {
		return fmt.Errorf("run %s is not awaiting its client", runID)
	}
	if c := ac.s.creators[runID]; me.PID == 0 || c != me {
		return fmt.Errorf("run %s was created by another process", runID)
	}
	delete(ac.s.restored, runID)
	ac.runID, ac.cgID = runID, ac.s.runCg[runID]
	return nil
}

// abandon ends a run whose client went away without "end", unless the
// node agent is shutting down (see the package comment on restarts).
func (ac *apiConn) abandon() {
	if ac.callID != "" && !ac.callDone {
		ac.callEnd(nil)
		return
	}
	if ac.runID == "" {
		return
	}
	ac.s.mu.Lock()
	closing := ac.s.closing
	ac.s.mu.Unlock()
	if closing {
		log.Printf("run api: run %s left running across node agent shutdown", ac.runID)
		return
	}
	log.Printf("run api: run %s: client disconnected; ending run", ac.runID)
	ac.s.forgetEndReason(ac.runID)
	ac.finish(nil)
}

// finish ends this connection's run.
func (ac *apiConn) finish(exitCode *int) {
	ac.s.endRun(ac.runID, exitCode)
	ac.runID = ""
}

// forgetEndReason drops a reason no client will collect.
func (s *RunAPIServer) forgetEndReason(runID string) {
	s.mu.Lock()
	delete(s.endReasons, runID)
	s.mu.Unlock()
}

// endRun records how a run ended, then kills what is left and removes the
// cgroup. The metadata must be in place before the rmdir, which is what
// makes the recorder write the timeline. A run's live nested runs end
// first, each with its own timeline. Ending a run that is not live does
// nothing: a nested run ended with its parent is ended again when its own
// client goes away.
func (s *RunAPIServer) endRun(runID string, exitCode *int) {
	s.mu.Lock()
	if !s.active[runID] {
		s.mu.Unlock()
		return
	}
	delete(s.active, runID) // from here on, this call owns the ending
	kids := append([]string{}, s.children[runID]...)
	cgID := s.runCg[runID]
	s.mu.Unlock()
	for _, k := range kids {
		s.endRun(k, nil)
	}

	if s.OnRunEnd != nil {
		s.OnRunEnd(runID, cgID)
	}
	end := time.Now().UTC()
	s.reg.Update(runID, func(m *RunMeta) {
		m.EndedAt = &end
		m.ExitCode = exitCode
	})
	if s.MCP != nil {
		s.MCP.EndRun(runID)
	}
	if s.cm != nil {
		if err := s.cm.DestroyRunCgroup(runID); err != nil {
			log.Printf("run api: run %s: %v", runID, err)
		}
	} else {
		// No rmdir will report the end: the metadata is in place, so
		// the recorder can finish the timeline.
		s.emit(EventRunEnd, runID, cgID)
	}
	s.mu.Lock()
	if t := s.tokOf[runID]; t != "" {
		delete(s.tokens, t)
		delete(s.tokOf, runID)
	}
	if b, ok := s.bound[runID]; ok {
		for cg, bb := range s.byCg {
			if bb == b {
				delete(s.byCg, cg)
			}
		}
		delete(s.bound, runID)
	}
	for cg, r := range s.runByCg {
		if r == runID {
			delete(s.runByCg, cg)
		}
	}
	delete(s.runCg, runID)
	delete(s.restored, runID)
	delete(s.creators, runID)
	delete(s.callSeq, runID)
	delete(s.liveCalls, runID)
	delete(s.children, runID)
	nested := false
	if p, ok := s.parentOf[runID]; ok {
		nested = true
		delete(s.parentOf, runID)
		kids := s.children[p]
		for i, k := range kids {
			if k == runID {
				s.children[p] = append(append([]string{}, kids[:i]...), kids[i+1:]...)
				break
			}
		}
	}
	s.mu.Unlock()
	s.saveGrants()
	if nested && s.OnNestedEnd != nil {
		s.OnNestedEnd(cgID)
	}
}

func (s *RunAPIServer) isNested(runID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.parentOf[runID]
	return ok
}

func contains(list []string, x string) bool {
	for _, v := range list {
		if v == x {
			return true
		}
	}
	return false
}

// descendants lists a run's live nested runs, at any depth. Called with
// s.mu held.
func (s *RunAPIServer) descendants(runID string) []string {
	var out []string
	for _, k := range s.children[runID] {
		out = append(out, k)
		out = append(out, s.descendants(k)...)
	}
	return out
}

// RunAPIClient is the client side of the run API.
type RunAPIClient struct {
	c     *net.UnixConn
	mc    *msgConn
	path  string
	runID string // from Create, to report the end after a node agent restart
}

// DialRunAPI connects to the node agent.
func DialRunAPI(path string) (*RunAPIClient, error) {
	c, err := net.DialUnix(apiNet, nil, &net.UnixAddr{Name: path, Net: apiNet})
	if err != nil {
		return nil, fmt.Errorf("cannot reach the node agent at %s (is it running?): %w", path, err)
	}
	return &RunAPIClient{c: c, mc: newMsgConn(c), path: path}, nil
}

// Close closes the connection. If the run has not ended, the node agent
// ends it.
func (rc *RunAPIClient) Close() error { return rc.c.Close() }

func (rc *RunAPIClient) call(req RunAPIRequest, fds ...int) (RunAPIResponse, error) {
	var resp RunAPIResponse
	msg, err := json.Marshal(req)
	if err != nil {
		return resp, err
	}
	if err := rc.mc.send(msg, fds...); err != nil {
		return resp, err
	}
	reply, _, err := rc.mc.recv()
	if err != nil {
		return resp, err
	}
	if err := json.Unmarshal(reply, &resp); err != nil {
		return resp, err
	}
	if !resp.OK {
		return resp, fmt.Errorf("node agent: %s", resp.Error)
	}
	return resp, nil
}

// Create asks for a new run, optionally requesting a profile.
func (rc *RunAPIClient) Create(command []string, cwd, profile string) (RunAPIResponse, error) {
	resp, err := rc.call(RunAPIRequest{Op: "create", Command: command, Cwd: cwd, Profile: profile})
	if err == nil {
		rc.runID = resp.RunID
	}
	return resp, err
}

// Profiles lists what the caller may request.
func (rc *RunAPIClient) Profiles() (RunAPIResponse, error) {
	return rc.call(RunAPIRequest{Op: "profiles"})
}

// Status returns the node's enforcement state.
func (rc *RunAPIClient) Status() (*NodeStatus, error) {
	r, err := rc.call(RunAPIRequest{Op: "status"})
	if err != nil {
		return nil, err
	}
	if r.Status == nil {
		return nil, fmt.Errorf("node agent sent no status")
	}
	return r.Status, nil
}

// Clamp layers a profile onto a live run.
func (rc *RunAPIClient) Clamp(runID, profile string) (RunAPIResponse, error) {
	return rc.call(RunAPIRequest{Op: "clamp", RunID: runID, ClampProfile: profile})
}

// RegisterMCP exposes stdio MCP servers for the run created on this
// connection.
func (rc *RunAPIClient) RegisterMCP(servers []MCPServerSpec) (RunAPIResponse, error) {
	return rc.call(RunAPIRequest{Op: "mcp_register", MCPServers: servers})
}

// Pins lists tool pins: those with a changed definition awaiting review,
// or all with all. Naming a tool returns its definitions too.
func (rc *RunAPIClient) Pins(server, tool string, all bool) (RunAPIResponse, error) {
	return rc.call(RunAPIRequest{Op: "pins", PinServer: server, PinTool: tool, PinsAll: all})
}

// ApprovePin makes a tool's changed definition its pin; with tool "",
// every changed tool on the server. hash, if set, must prefix the pending
// definition's hash.
func (rc *RunAPIClient) ApprovePin(server, tool, hash string) (RunAPIResponse, error) {
	return rc.call(RunAPIRequest{Op: "pin_approve", PinServer: server, PinTool: tool, PinHash: hash})
}

// Pending lists requests held for a decision; with all, recently settled
// ones too (milestone 5.5).
func (rc *RunAPIClient) Pending(all bool) (RunAPIResponse, error) {
	return rc.call(RunAPIRequest{Op: "pending", AsksAll: all})
}

// DecideAsk approves or denies a held request; remember makes the
// decision stand for the rest of the run.
func (rc *RunAPIClient) DecideAsk(id string, approve, remember bool) (RunAPIResponse, error) {
	return rc.call(RunAPIRequest{Op: "ask_decide", AskID: id, Approve: approve, Remember: remember})
}

// Revoke denies all further egress for a live run.
func (rc *RunAPIClient) Revoke(runID string) (RunAPIResponse, error) {
	return rc.call(RunAPIRequest{Op: "revoke", RunID: runID})
}

// Attach moves the caller's child, identified by pidfd, into the run.
func (rc *RunAPIClient) Attach(pidfd int) error {
	_, err := rc.call(RunAPIRequest{Op: "attach"}, pidfd)
	return err
}

// End reports the exit code (nil if unknown) and ends the run. It returns
// why the node agent had ended it already, if it had.
//
// If the node agent restarted during the run, the connection is gone; the
// new node agent restored the run (milestone 6.1), so End reconnects and
// claims it by its id, as the process that created it.
func (rc *RunAPIClient) End(exitCode *int) (string, error) {
	resp, err := rc.call(RunAPIRequest{Op: "end", ExitCode: exitCode})
	if err == nil || resp.Error != "" || rc.runID == "" || rc.path == "" {
		return resp.EndReason, err
	}
	nc, derr := DialRunAPI(rc.path)
	if derr != nil {
		return "", fmt.Errorf("%w (and reconnecting: %v)", err, derr)
	}
	defer nc.Close()
	resp, err2 := nc.call(RunAPIRequest{Op: "end", RunID: rc.runID, ExitCode: exitCode})
	if err2 != nil {
		return "", fmt.Errorf("%w (and after reconnecting: %v)", err, err2)
	}
	return resp.EndReason, nil
}

// ActiveRuns counts runs whose agentctl connection is open.
func (s *RunAPIServer) ActiveRuns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.active)
}

// maxLiveCalls bounds a run's tool calls in progress at once.
const maxLiveCalls = 256

// call opens a tool call (milestone 4.5): a cgroup of its own below the
// caller's run, run-<id>/call-<n>, for the process the caller attaches
// next. The caller must be inside the run; the run is found from its
// cgroup, never from the request. Events from the call's processes are
// the run's, attributed to the call.
func (ac *apiConn) call(req RunAPIRequest) RunAPIResponse {
	if ac.s.cm == nil {
		return fail("tool calls need cgroup identity")
	}
	if ac.runID != "" || ac.callID != "" {
		return fail("this connection already has a run or a call")
	}
	cg, err := procCgroup(int(ac.cred.Pid))
	if err != nil {
		return fail("cannot read caller's cgroup: %v", err)
	}
	runID := ac.s.runOfCgroupPath(cg)
	if runID == "" {
		return fail("a tool call must be started from inside a run")
	}
	runPath, ok := ac.s.cm.GetRunCgroupPath(runID)
	ac.s.mu.Lock()
	live := ac.s.active[runID]
	b := ac.s.bound[runID]
	if ok && live && ac.s.liveCalls[runID] >= maxLiveCalls {
		ok = false
		err = fmt.Errorf("run %s has %d tool calls in progress", runID, maxLiveCalls)
	}
	var n int
	if ok && live {
		ac.s.callSeq[runID]++
		n = ac.s.callSeq[runID]
		ac.s.liveCalls[runID]++
	}
	ac.s.mu.Unlock()
	switch {
	case err != nil:
		return fail("%v", err)
	case !ok || !live:
		return fail("run %s is not live", runID)
	case b != nil && ac.cred.Uid != 0 && int(ac.cred.Uid) != b.uid:
		ac.releaseCall(runID)
		return fail("run %s belongs to another user", runID)
	}
	callID := fmt.Sprintf("call-%d", n)
	path := filepath.Join(runPath, callID)
	if err := os.Mkdir(path, 0o755); err != nil {
		ac.releaseCall(runID)
		return fail("failed to create call cgroup: %v", err)
	}
	id, err := GetCgroupID(path)
	if err != nil {
		os.Remove(path)
		ac.releaseCall(runID)
		return fail("%v", err)
	}
	ac.s.addRunCgroup(runID, id)
	ac.s.reg.AddCall(runID, CallMeta{ID: callID, Name: req.CallName, Command: req.Command, CgroupID: id, StartedAt: time.Now().UTC()})
	ac.callID, ac.callRun, ac.callPath = callID, runID, path
	return RunAPIResponse{OK: true, RunID: runID, CallID: callID, CgroupID: id}
}

func (ac *apiConn) releaseCall(runID string) {
	ac.s.mu.Lock()
	if ac.s.liveCalls[runID] > 0 {
		ac.s.liveCalls[runID]--
	}
	ac.s.mu.Unlock()
}

// callEnd records how the call ended, kills what is left in its cgroup,
// and removes the cgroup. Its events stay attributed: the registry keeps
// the call until the run's timeline is written.
func (ac *apiConn) callEnd(exitCode *int) RunAPIResponse {
	if ac.callID == "" {
		return fail("no call")
	}
	if ac.callDone {
		return RunAPIResponse{OK: true, RunID: ac.callRun, CallID: ac.callID}
	}
	ac.callDone = true
	ac.s.reg.EndCall(ac.callRun, ac.callID, exitCode)
	if err := killAndRemoveCgroup(ac.callPath); err != nil {
		log.Printf("run api: run %s %s: %v", ac.callRun, ac.callID, err)
	}
	ac.releaseCall(ac.callRun)
	return RunAPIResponse{OK: true, RunID: ac.callRun, CallID: ac.callID}
}

// Nesting limits (milestone 4.6): how deep runs nest below a top-level
// run (MAX_NEST in agent_audit.c), and the exec layers the kernel holds
// for a run (MAX_EXEC_LAYERS).
const (
	maxNest             = 3
	maxKernelExecLayers = 6
)

// runOfCgroupPath returns the nearest run a cgroup path (relative to the
// cgroup root) is in: the deepest run-<id> along it, so a nested run's
// processes and calls are its own, not its parent's. "" outside a run.
func (s *RunAPIServer) runOfCgroupPath(cg string) string {
	if !s.inAgents(cg) {
		return ""
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(cg, s.agentsRel), "/")
	runID := ""
	for i, part := range strings.Split(rest, "/") {
		id, ok := strings.CutPrefix(part, RunPrefix)
		if !ok {
			if i == 0 {
				return "" // not in a run
			}
			continue
		}
		runID = id
	}
	return runID
}

// runDepth counts the runs a cgroup path is nested in below its
// top-level run: 0 for a top-level run or its calls.
func (s *RunAPIServer) runDepth(cg string) int {
	rest := strings.TrimPrefix(strings.TrimPrefix(cg, s.agentsRel), "/")
	n := 0
	for _, part := range strings.Split(rest, "/") {
		if strings.HasPrefix(part, RunPrefix) {
			n++
		}
	}
	return max(n-1, 0)
}

// Call opens a tool call in the caller's run; Attach then moves the
// call's process in, and CallEnd closes it.
func (rc *RunAPIClient) Call(name string, command []string) (RunAPIResponse, error) {
	return rc.call(RunAPIRequest{Op: "call", CallName: name, Command: command})
}

// CallEnd closes the call opened on this connection.
func (rc *RunAPIClient) CallEnd(exitCode *int) error {
	_, err := rc.call(RunAPIRequest{Op: "call_end", ExitCode: exitCode})
	return err
}

// asks lists and decides requests held for a person (milestone 5.5). A
// decision grants what policy did not, so it is never taken from inside
// a run: an agent must not approve its own requests. With cgroup identity
// that is known from the caller's cgroup, and a run's owner may decide on
// its requests. With credential identity a run's processes are in no
// cgroup and run as its owner, so only root decides.
func (ac *apiConn) asks(req RunAPIRequest) RunAPIResponse {
	q := ac.s.Asks
	if q == nil {
		return fail("this node agent holds no requests for approval (no proxy and no MCP gateway)")
	}
	uid := int(ac.cred.Uid)
	if ac.s.cm != nil {
		cg, err := procCgroup(int(ac.cred.Pid))
		if err != nil {
			return fail("cannot read caller's cgroup: %v", err)
		}
		if ac.s.inAgents(cg) {
			return fail("requests held for approval cannot be seen or decided from inside a run")
		}
	}
	see := func(p PendingAsk) bool { return uid == 0 || p.UID == uid }
	if req.Op == "pending" {
		return RunAPIResponse{OK: true, Asks: q.List(see, req.AsksAll)}
	}
	if req.AskID == "" {
		return fail("ask_decide needs a request id (agentctl pending lists them)")
	}
	if uid != 0 && ac.s.cm == nil {
		return fail("with credential identity only root decides on held requests: a run's processes run as its owner, " +
			"so a decision by the owner could be the agent's own. Use sudo agentctl")
	}
	by := fmt.Sprintf("uid %d", uid)
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		by = fmt.Sprintf("%s (uid %d)", u.Username, uid)
	}
	p, err := q.Decide(req.AskID, req.Approve, req.Remember, by, func(p PendingAsk) error {
		if !see(p) {
			return fmt.Errorf("request %s belongs to another user's run", req.AskID)
		}
		return nil
	})
	if err != nil {
		return fail("%v", err)
	}
	log.Printf("run api: %s %s request %s of run %s (%s)%s", by, map[bool]string{true: "approved", false: "denied"}[req.Approve],
		p.ID, p.RunID, p.What, map[bool]string{true: ", remembered for the run", false: ""}[req.Remember])
	return RunAPIResponse{OK: true, Asks: []PendingAsk{p}}
}
