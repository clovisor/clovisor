// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
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
	Op       string   `json:"op"` // create, attach, end
	Command  []string `json:"command,omitempty"`
	Cwd      string   `json:"cwd,omitempty"`
	ExitCode *int     `json:"exit_code,omitempty"`
}

// RunAPIResponse is the agent's reply to each request.
type RunAPIResponse struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	RunID    string `json:"run_id,omitempty"`
	CgroupID uint64 `json:"cgroup_id,omitempty"`
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

	mu      sync.Mutex
	conns   map[*net.UnixConn]struct{}
	active  map[string]bool // runs owned by a live connection
	closing bool
	done    chan struct{}
	wg      sync.WaitGroup
}

// reapInterval is how often orphaned run cgroups are checked.
const reapInterval = 5 * time.Second

// NewRunAPIServer listens on path. The socket is world-connectable:
// every request is checked against the caller's kernel credentials, and
// a caller can only ever confine its own children.
func NewRunAPIServer(path string, cm *CgroupManager, reg *RunRegistry) (*RunAPIServer, error) {
	rel, err := filepath.Rel(CgroupV2Root, cm.GetAgentsDir())
	if err != nil {
		return nil, err
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
	ln, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
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
		agentsRel: "/" + rel,
		ln:        ln,
		path:      path,
		conns:     map[*net.UnixConn]struct{}{},
		active:    map[string]bool{},
		done:      make(chan struct{}),
	}, nil
}

// reap removes run cgroups that no connection owns once they are empty:
// runs left behind by an earlier node agent, or by a client whose end
// failed. Removing the cgroup is what finalizes the run's timeline.
func (s *RunAPIServer) reap() {
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

func peerCred(c *net.UnixConn) (*unix.Ucred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	return cred, serr
}

// procCgroup returns a process's cgroup v2 path, e.g. /user.slice/x.scope.
func procCgroup(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::"), nil
		}
	}
	return "", fmt.Errorf("pid %d has no cgroup v2 membership", pid)
}

// procStatus returns the parent pid and real uid of a process.
func procStatus(pid int) (ppid int, uid int, err error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	ppid, uid = -1, -1
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(v)
		if len(fields) == 0 {
			continue
		}
		switch k {
		case "PPid":
			ppid, _ = strconv.Atoi(fields[0])
		case "Uid":
			uid, _ = strconv.Atoi(fields[0])
		}
	}
	if ppid < 0 || uid < 0 {
		return 0, 0, fmt.Errorf("cannot parse /proc/%d/status", pid)
	}
	return ppid, uid, sc.Err()
}

// pidfdPid returns the pid a pidfd refers to.
func pidfdPid(fd int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "Pid:"); ok {
			pid, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || pid <= 0 {
				return 0, fmt.Errorf("fd %d is not a live pidfd", fd)
			}
			return pid, nil
		}
	}
	return 0, fmt.Errorf("fd %d is not a pidfd", fd)
}

func (s *RunAPIServer) inAgents(cg string) bool {
	return cg == s.agentsRel || strings.HasPrefix(cg, s.agentsRel+"/")
}

type apiConn struct {
	s        *RunAPIServer
	c        *net.UnixConn
	cred     *unix.Ucred
	runID    string
	runPath  string
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

	buf := make([]byte, maxAPIMessage)
	oob := make([]byte, unix.CmsgSpace(4*4))
	for {
		n, oobn, flags, _, err := c.ReadMsgUnix(buf, oob)
		fds := parseFDs(oob[:oobn])
		if err != nil || n == 0 {
			closeFDs(fds)
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("run api: read: %v", err)
			}
			return
		}
		var resp RunAPIResponse
		var req RunAPIRequest
		switch {
		case flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0:
			resp.Error = "message too large"
		default:
			if err := json.Unmarshal(buf[:n], &req); err != nil {
				resp.Error = "bad request: " + err.Error()
			} else {
				resp = ac.dispatch(req, fds)
				fds = nil // dispatch owns them
			}
		}
		closeFDs(fds)
		out, _ := json.Marshal(resp)
		if _, err := c.Write(out); err != nil {
			return
		}
		if req.Op == "end" && resp.OK {
			return
		}
	}
}

func parseFDs(oob []byte) []int {
	if len(oob) == 0 {
		return nil
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	var fds []int
	for _, m := range msgs {
		if got, err := unix.ParseUnixRights(&m); err == nil {
			fds = append(fds, got...)
		}
	}
	return fds
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		unix.Close(fd)
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
		if len(fds) != 1 {
			return fail("attach needs exactly one pidfd, got %d fds", len(fds))
		}
		return ac.attach(fds[0])
	case "end":
		return ac.end(req.ExitCode)
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
	// Nested runs belong to sub-agent attenuation (design §7.8).
	cg, err := procCgroup(int(ac.cred.Pid))
	if err != nil {
		return fail("cannot read caller's cgroup: %v", err)
	}
	if ac.s.inAgents(cg) {
		return fail("caller is inside a run (%s); runs cannot create runs", cg)
	}

	runID, err := NewRunID()
	if err != nil {
		return fail("%v", err)
	}
	ac.s.mu.Lock()
	path, id, err := ac.s.cm.CreateRunCgroup(runID)
	if err == nil {
		ac.s.active[runID] = true
	}
	ac.s.mu.Unlock()
	if err != nil {
		return fail("%v", err)
	}
	ac.runID, ac.runPath = runID, path
	ac.s.reg.Put(RunMeta{
		RunID:     runID,
		Command:   req.Command,
		Cwd:       req.Cwd,
		UID:       int(ac.cred.Uid),
		StartedAt: time.Now().UTC(),
	})
	log.Printf("run api: run %s created for uid %d pid %d", runID, ac.cred.Uid, ac.cred.Pid)
	return RunAPIResponse{OK: true, RunID: runID, CgroupID: id}
}

// attach moves the process behind pidfd into the run. The process must be
// a direct child of the caller, have the caller's real uid, and not
// already be in a run.
func (ac *apiConn) attach(pidfd int) RunAPIResponse {
	if ac.runID == "" {
		return fail("no run: send create first")
	}
	if ac.attached {
		return fail("run %s already has its process", ac.runID)
	}
	pid, err := pidfdPid(pidfd)
	if err != nil {
		return fail("%v", err)
	}
	ppid, uid, err := procStatus(pid)
	if err != nil {
		return fail("%v", err)
	}
	if ppid != int(ac.cred.Pid) {
		return fail("pid %d is not a child of the caller", pid)
	}
	if uid != int(ac.cred.Uid) {
		return fail("pid %d does not belong to uid %d", pid, ac.cred.Uid)
	}
	if cg, err := procCgroup(pid); err != nil || ac.s.inAgents(cg) {
		return fail("pid %d is already in a run, or its cgroup is unreadable", pid)
	}

	if err := os.WriteFile(filepath.Join(ac.runPath, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0); err != nil {
		return fail("failed to move pid %d into run: %v", pid, err)
	}
	// The pid cannot have been reused between the checks and the move
	// while the pidfd's process is alive: an unreaped process keeps its
	// pid. Confirm it still is.
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		log.Printf("run api: run %s: process %d exited during attach; the pid may have been reused", ac.runID, pid)
		return fail("process exited during attach")
	}
	ac.attached = true
	return RunAPIResponse{OK: true, RunID: ac.runID}
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
	if err := ac.s.cm.DestroyRunCgroup(ac.runID); err != nil {
		log.Printf("run api: run %s: %v", ac.runID, err)
	}
	ac.s.mu.Lock()
	delete(ac.s.active, ac.runID)
	ac.s.mu.Unlock()
	ac.runID = ""
}

// RunAPIClient is the client side of the run API.
type RunAPIClient struct {
	c *net.UnixConn
}

// DialRunAPI connects to the node agent.
func DialRunAPI(path string) (*RunAPIClient, error) {
	c, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		return nil, fmt.Errorf("cannot reach the node agent at %s (is it running?): %w", path, err)
	}
	return &RunAPIClient{c: c}, nil
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
	var oob []byte
	if len(fds) > 0 {
		oob = unix.UnixRights(fds...)
	}
	if _, _, err := rc.c.WriteMsgUnix(msg, oob, nil); err != nil {
		return resp, err
	}
	buf := make([]byte, maxAPIMessage)
	n, err := rc.c.Read(buf)
	if err != nil {
		return resp, err
	}
	if err := json.NewDecoder(bytes.NewReader(buf[:n])).Decode(&resp); err != nil {
		return resp, err
	}
	if !resp.OK {
		return resp, fmt.Errorf("node agent: %s", resp.Error)
	}
	return resp, nil
}

// Create asks for a new run.
func (rc *RunAPIClient) Create(command []string, cwd string) (RunAPIResponse, error) {
	return rc.call(RunAPIRequest{Op: "create", Command: command, Cwd: cwd})
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
