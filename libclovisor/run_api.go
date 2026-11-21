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
	"path/filepath"
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
	Op       string   `json:"op"` // create, attach, end, profiles, clamp, revoke, mcp_register, pins, pin_approve
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
}

// RunAPIResponse is the agent's reply to each request.
type RunAPIResponse struct {
	OK       bool       `json:"ok"`
	Error    string     `json:"error,omitempty"`
	RunID    string     `json:"run_id,omitempty"`
	CgroupID uint64     `json:"cgroup_id,omitempty"`
	Policy   *RunPolicy `json:"policy,omitempty"` // create, clamp, revoke
	Proxy    string     `json:"proxy,omitempty"`  // create: the node's proxy URL, if any
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
}

// RunRegistry holds metadata for runs created through the API until the
// recorder has written their timelines. Safe for concurrent use.
type RunRegistry struct {
	mu sync.Mutex
	m  map[string]RunMeta
}

// NewRunRegistry returns an empty registry.
func NewRunRegistry() *RunRegistry { return &RunRegistry{m: map[string]RunMeta{}} }

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
	// MCP is the local MCP gateway, if enabled.
	MCP *MCPGateway
	// Pins is the node's tool-definition pin store, if MCP is governed.
	Pins *PinStore
	// TrustBundle and NodeCACert are handed to runs when the proxy
	// terminates TLS.
	TrustBundle, NodeCACert string
	// Events receives run start and end with credential identity, where
	// no cgroup mkdir or rmdir reports them.
	Events chan<- AuditEvent

	nextCg uint64            // credential identity: synthetic run ids
	tokens map[string]string // credential identity: token -> run id
	tokOf  map[string]string // run id -> token

	mu      sync.Mutex
	conns   map[*net.UnixConn]struct{}
	active  map[string]bool // runs owned by a live connection
	bound   map[string]*boundRun
	byCg    map[uint64]*boundRun
	runByCg map[uint64]string // every live run, profiled or not, and its child cgroups
	runCg   map[string]uint64 // run id -> the run's own cgroup id
	closing bool
	done    chan struct{}
	wg      sync.WaitGroup
}

// boundRun is a live run's effective policy.
type boundRun struct {
	runID    string
	uid      int
	cgroupID uint64
	eff      *policy.Effective // replaced, never mutated, under RunAPIServer.mu
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
		cm:        cm,
		reg:       reg,
		agentsRel: rel,
		ln:        ln,
		path:      path,
		conns:     map[*net.UnixConn]struct{}{},
		active:    map[string]bool{},
		bound:     map[string]*boundRun{},
		byCg:      map[uint64]*boundRun{},
		runByCg:   map[uint64]string{},
		runCg:     map[string]uint64{},
		tokens:    map[string]string{},
		tokOf:     map[string]string{},
		nextCg:    credentialCgBase,
		done:      make(chan struct{}),
	}, nil
}

// reap removes run cgroups that no connection owns once they are empty:
// runs left behind by an earlier node agent, or by a client whose end
// failed. Removing the cgroup is what finalizes the run's timeline.
func (s *RunAPIServer) reap() {
	if s.cm == nil {
		return
	}
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
		if req.Op == "end" && resp.OK {
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
		return ac.attach(fds[0])
	case "end":
		return ac.end(req.ExitCode)
	case "profiles":
		return ac.profiles()
	case "clamp", "revoke":
		return ac.clamp(req)
	case "mcp_register":
		return ac.mcpRegister(req)
	case "pins", "pin_approve":
		return ac.pins(req)
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
	// A run must not be able to start another run: that would let a
	// confined process move its children out from under its own policy.
	// Nested runs belong to sub-agent attenuation (design §7.8). With
	// credential identity there is no cgroup to check, so a run can start
	// another run within its user's ceiling, escaping its own clamps; the
	// receipt says identity is a claim there.
	if ac.s.cm != nil {
		cg, err := procCgroup(int(ac.cred.Pid))
		if err != nil {
			return fail("cannot read caller's cgroup: %v", err)
		}
		if ac.s.inAgents(cg) {
			return fail("caller is inside a run (%s); runs cannot create runs", cg)
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

	runID, err := NewRunID()
	if err != nil {
		return fail("%v", err)
	}
	ac.s.mu.Lock()
	var path, token string
	var id uint64
	if ac.s.cm != nil {
		path, id, err = ac.s.cm.CreateRunCgroup(runID)
	} else {
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
		ac.s.runByCg[id] = runID
		ac.s.runCg[runID] = id
		if binding != nil {
			b := &boundRun{runID: runID, uid: int(ac.cred.Uid), cgroupID: id, eff: binding.Effective}
			ac.s.bound[runID] = b
			ac.s.byCg[id] = b
		}
	}
	ac.s.mu.Unlock()
	if err != nil {
		return fail("%v", err)
	}
	ac.runID, ac.runPath, ac.cgID, ac.cwd = runID, path, id, req.Cwd
	rp := runPolicyRecord(binding)
	ac.s.reg.Put(RunMeta{
		RunID:     runID,
		Command:   req.Command,
		Cwd:       req.Cwd,
		UID:       int(ac.cred.Uid),
		StartedAt: time.Now().UTC(),
		Policy:    rp,
	})
	if ac.s.cm == nil {
		ac.s.emit(EventRunStart, runID, id)
	}
	granted := "unprofiled"
	if rp != nil {
		granted = rp.Layers[0].Profile + "@" + rp.Layers[0].Version + " (" + rp.Reason + ")"
	}
	log.Printf("run api: run %s created for uid %d pid %d: %s", runID, ac.cred.Uid, ac.cred.Pid, granted)
	resp := RunAPIResponse{OK: true, RunID: runID, CgroupID: id, Policy: rp, Proxy: ac.s.ProxyURL,
		TrustBundle: ac.s.TrustBundle, NodeCACert: ac.s.NodeCACert, Identity: "cgroup"}
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
	}
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

	ac.s.mu.Lock()
	b, ok := ac.s.bound[runID]
	if ok && ac.cred.Uid != 0 && int(ac.cred.Uid) != b.uid {
		ac.s.mu.Unlock()
		return fail("run %s belongs to another user", runID)
	}
	if ok {
		b.eff = b.eff.With(layer)
	}
	ac.s.mu.Unlock()
	if !ok {
		return fail("no live profiled run %s", runID)
	}

	at := time.Now().UTC()
	var rp *RunPolicy
	ac.s.reg.Update(runID, func(m *RunMeta) {
		if m.Policy != nil {
			// Copy on write: the recorder may hold the old record.
			np := *m.Policy
			np.Layers = append(append([]PolicyLayer{}, m.Policy.Layers...), layerRecord(layer, at))
			m.Policy = &np
			rp = &np
		}
	})
	log.Printf("run api: run %s: %s %s", runID, layer.Source, layer.Profile.Name)
	return RunAPIResponse{OK: true, RunID: runID, Policy: rp}
}

func (ac *apiConn) end(exitCode *int) RunAPIResponse {
	if ac.runID == "" {
		return fail("no run")
	}
	runID := ac.runID
	ac.finish(exitCode)
	return RunAPIResponse{OK: true, RunID: runID}
}

// abandon ends a run whose client went away without "end", unless the
// node agent is shutting down (see the package comment on restarts).
func (ac *apiConn) abandon() {
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
	ac.finish(nil)
}

// finish records how the run ended, then kills what is left and removes
// the cgroup. The metadata must be in place before the rmdir, which is
// what makes the recorder write the timeline.
func (ac *apiConn) finish(exitCode *int) {
	end := time.Now().UTC()
	ac.s.reg.Update(ac.runID, func(m *RunMeta) {
		m.EndedAt = &end
		m.ExitCode = exitCode
	})
	if ac.s.MCP != nil {
		ac.s.MCP.EndRun(ac.runID)
	}
	if ac.s.cm != nil {
		if err := ac.s.cm.DestroyRunCgroup(ac.runID); err != nil {
			log.Printf("run api: run %s: %v", ac.runID, err)
		}
	} else {
		// No rmdir will report the end: the metadata is in place, so
		// the recorder can finish the timeline.
		ac.s.emit(EventRunEnd, ac.runID, ac.cgID)
	}
	ac.s.mu.Lock()
	if t := ac.s.tokOf[ac.runID]; t != "" {
		delete(ac.s.tokens, t)
		delete(ac.s.tokOf, ac.runID)
	}
	delete(ac.s.active, ac.runID)
	if b, ok := ac.s.bound[ac.runID]; ok {
		for cg, bb := range ac.s.byCg {
			if bb == b {
				delete(ac.s.byCg, cg)
			}
		}
		delete(ac.s.bound, ac.runID)
	}
	for cg, r := range ac.s.runByCg {
		if r == ac.runID {
			delete(ac.s.runByCg, cg)
		}
	}
	delete(ac.s.runCg, ac.runID)
	ac.s.mu.Unlock()
	ac.runID = ""
}

// RunAPIClient is the client side of the run API.
type RunAPIClient struct {
	c  *net.UnixConn
	mc *msgConn
}

// DialRunAPI connects to the node agent.
func DialRunAPI(path string) (*RunAPIClient, error) {
	c, err := net.DialUnix(apiNet, nil, &net.UnixAddr{Name: path, Net: apiNet})
	if err != nil {
		return nil, fmt.Errorf("cannot reach the node agent at %s (is it running?): %w", path, err)
	}
	return &RunAPIClient{c: c, mc: newMsgConn(c)}, nil
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
	return rc.call(RunAPIRequest{Op: "create", Command: command, Cwd: cwd, Profile: profile})
}

// Profiles lists what the caller may request.
func (rc *RunAPIClient) Profiles() (RunAPIResponse, error) {
	return rc.call(RunAPIRequest{Op: "profiles"})
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

// Revoke denies all further egress for a live run.
func (rc *RunAPIClient) Revoke(runID string) (RunAPIResponse, error) {
	return rc.call(RunAPIRequest{Op: "revoke", RunID: runID})
}

// Attach moves the caller's child, identified by pidfd, into the run.
func (rc *RunAPIClient) Attach(pidfd int) error {
	_, err := rc.call(RunAPIRequest{Op: "attach"}, pidfd)
	return err
}

// End reports the exit code (nil if unknown) and ends the run.
func (rc *RunAPIClient) End(exitCode *int) error {
	_, err := rc.call(RunAPIRequest{Op: "end", ExitCode: exitCode})
	return err
}
