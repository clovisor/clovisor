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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// The local MCP gateway (design §8.3, milestone 2.5). It runs in the node
// agent, so the governed agent cannot tamper with it, and exposes each
// stdio MCP server a run registered over streamable HTTP on loopback:
//
//	http://<listen>/mcp/<name>
//
// The server process is started on first use as the run's user, in a
// child cgroup of the run (so its own egress is the run's, through the
// proxy), and its JSON-RPC is enforced on the way through: tools/call,
// resources/read, tools/list (filtering and pinning), and sampling.
//
// The bypass is the one §8.3 names: the agent can spawn the server
// itself instead. Exec policy is the backstop (Phase 4).

// MCPServerSpec is a stdio server a run registers.
type MCPServerSpec struct {
	Name    string            `json:"name"`
	Command []string          `json:"command"` // absolute path first
	Env     map[string]string `json:"env,omitempty"`
}

// MCPRegistration is the gateway's answer for one server.
type MCPRegistration struct {
	Name  string `json:"name"`
	URL   string `json:"url,omitempty"`
	Error string `json:"error,omitempty"`
	// WouldDeny lists audit-mode layers that would refuse the server.
	WouldDeny []string `json:"would_deny,omitempty"`
}

// MCPData is one gateway decision, for the run's timeline.
type MCPData struct {
	Server    string // the harness's name for it
	Method    string // tools/call, resources/read, tools/list, sampling/createMessage, register
	Name      string // tool name or resource URI
	Decision  string
	Enforced  bool
	Rule      string
	Layer     string
	WouldDeny []string
	Reason    string // e.g. "tool definition changed since pinned"
}

var mcpNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)

type mcpRun struct {
	runID   string
	cgPath  string
	cgID    uint64
	uid     int
	gid     int
	groups  []int
	cwd     string
	servers map[string]*mcpServer
}

type mcpServer struct {
	run  *mcpRun
	spec MCPServerSpec

	mu      sync.Mutex
	proc    *mcpProc
	drifted map[string]bool // tools whose definition changed since pinned
}

// MCPGateway serves registered stdio servers to their runs.
type MCPGateway struct {
	api    *RunAPIServer
	events chan<- AuditEvent
	pins   *PinStore
	base   string // http://127.0.0.1:18100

	mu   sync.Mutex
	runs map[string]*mcpRun

	srv *http.Server
	ln  net.Listener

	// launch prepares a server's command; replaced in tests, which cannot
	// create cgroups or change uid.
	launch func(srv *mcpServer) (cmd *exec.Cmd, cleanup func(), err error)
}

// NewMCPGateway listens on addr.
func NewMCPGateway(api *RunAPIServer, addr netip.AddrPort, pins *PinStore, events chan<- AuditEvent) (*MCPGateway, error) {
	ln, err := net.Listen("tcp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("mcp gateway: %w", err)
	}
	g := &MCPGateway{api: api, events: events, pins: pins, base: "http://" + addr.String(), runs: map[string]*mcpRun{}, ln: ln}
	g.srv = &http.Server{Handler: http.HandlerFunc(g.serveHTTP), ReadHeaderTimeout: 10 * time.Second}
	g.launch = g.launchGoverned
	return g, nil
}

// Serve blocks until Close.
func (g *MCPGateway) Serve() error {
	if err := g.srv.Serve(g.ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Close stops the gateway and its servers.
func (g *MCPGateway) Close() {
	g.srv.Close()
	g.mu.Lock()
	runs := g.runs
	g.runs = map[string]*mcpRun{}
	g.mu.Unlock()
	for _, r := range runs {
		r.stop()
	}
}

func (r *mcpRun) stop() {
	for _, s := range r.servers {
		s.mu.Lock()
		if s.proc != nil {
			s.proc.kill()
			s.proc = nil
		}
		s.mu.Unlock()
	}
}

// EndRun stops a run's servers; its cgroup is about to be removed.
func (g *MCPGateway) EndRun(runID string) {
	g.mu.Lock()
	r := g.runs[runID]
	delete(g.runs, runID)
	g.mu.Unlock()
	if r != nil {
		r.stop()
	}
}

func (g *MCPGateway) record(r *mcpRun, d MCPData) {
	if g.events == nil {
		return
	}
	select {
	case g.events <- AuditEvent{Type: EventMCP, Timestamp: time.Now(), CgroupID: r.cgID, RunCgroupID: r.cgID, Data: d}:
	default:
	}
}

func (g *MCPGateway) effective(runID string) *policy.Effective { return g.api.effectiveOf(runID) }

func decideMCP(eff *policy.Effective, r policy.MCPRequest) policy.EffectiveDecision {
	if eff == nil { // unprofiled run: allowed, recorded
		return policy.EffectiveDecision{Decision: policy.Decision{Action: policy.ActionAllow}}
	}
	return eff.DecideMCP(r)
}

func mcpData(server, method, name string, d policy.EffectiveDecision) MCPData {
	return MCPData{Server: server, Method: method, Name: name, Decision: d.Action, Enforced: d.Enforced,
		Rule: d.Rule, Layer: d.Layer, WouldDeny: d.WouldDeny}
}

// Register records a run's stdio servers, refusing those its policy
// refuses. Each accepted server gets a URL.
func (g *MCPGateway) Register(run *mcpRun, specs []MCPServerSpec) []MCPRegistration {
	eff := g.effective(run.runID)
	g.mu.Lock()
	if existing, ok := g.runs[run.runID]; ok {
		run = existing
	} else {
		run.servers = map[string]*mcpServer{}
		g.runs[run.runID] = run
	}
	g.mu.Unlock()

	var out []MCPRegistration
	for _, s := range specs {
		reg := MCPRegistration{Name: s.Name}
		switch {
		case !mcpNameRE.MatchString(s.Name):
			reg.Error = "server names may use letters, digits, '.', '_' and '-'"
		case len(s.Command) == 0 || !filepath.IsAbs(s.Command[0]):
			reg.Error = "command must start with an absolute path"
		case run.servers[s.Name] != nil:
			reg.Error = "already registered"
		}
		if reg.Error != "" {
			out = append(out, reg)
			continue
		}
		d := decideMCP(eff, policy.MCPRequest{Kind: "server", Server: s.Name, Argv: s.Command})
		g.record(run, mcpData(s.Name, "register", strings.Join(s.Command, " "), d))
		if !d.Allowed() {
			reg.Error = d.Message
			out = append(out, reg)
			continue
		}
		run.servers[s.Name] = &mcpServer{run: run, spec: s, drifted: map[string]bool{}}
		reg.URL = g.base + "/mcp/" + s.Name
		reg.WouldDeny = d.WouldDeny
		out = append(out, reg)
	}
	return out
}

// identify returns the run of the HTTP client, by its socket's cgroup.
func (g *MCPGateway) identify(r *http.Request) (string, error) {
	local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return "", fmt.Errorf("no local address")
	}
	src, err1 := netip.ParseAddrPort(r.RemoteAddr)
	dst, err2 := netip.ParseAddrPort(local.String())
	if err1 != nil || err2 != nil {
		return "", fmt.Errorf("bad addresses")
	}
	cg, err := SockCgroup(src, dst)
	if err != nil {
		return "", err
	}
	runID, _, _, isRun := g.api.RunFor(cg)
	if !isRun {
		return "", fmt.Errorf("not a run")
	}
	return runID, nil
}

type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

func (m *rpcMsg) isRequest() bool  { return m.Method != "" && len(m.ID) > 0 }
func (m *rpcMsg) isResponse() bool { return m.Method == "" && len(m.ID) > 0 }

func rpcError(id json.RawMessage, code int, msg string) []byte {
	b, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": id, "error": map[string]interface{}{"code": code, "message": msg}})
	return b
}

// toolDenied is a tools/call result the model reads: the narration of
// design §7.7, delivered where an agent looks for it.
func toolDenied(id json.RawMessage, msg string) []byte {
	b, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": map[string]interface{}{
		"isError": true,
		"content": []interface{}{map[string]interface{}{"type": "text", "text": msg}},
	}})
	return b
}

func httpRPCError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(rpcError(json.RawMessage("null"), -32000, msg))
}

func (g *MCPGateway) serveHTTP(w http.ResponseWriter, r *http.Request) {
	name, ok := strings.CutPrefix(r.URL.Path, "/mcp/")
	if !ok || name == "" {
		httpRPCError(w, http.StatusNotFound, "use /mcp/<server>")
		return
	}
	runID, err := g.identify(r)
	if err != nil {
		httpRPCError(w, http.StatusForbidden, "This MCP gateway serves governed agent runs only ("+err.Error()+").")
		return
	}
	g.mu.Lock()
	run := g.runs[runID]
	var srv *mcpServer
	if run != nil {
		srv = run.servers[name]
	}
	g.mu.Unlock()
	if srv == nil {
		httpRPCError(w, http.StatusNotFound, "MCP server "+name+" is not registered for this run.")
		return
	}
	switch r.Method {
	case http.MethodPost:
		g.post(w, r, srv)
	case http.MethodGet:
		g.stream(w, r, srv)
	case http.MethodDelete:
		srv.mu.Lock()
		if srv.proc != nil {
			srv.proc.kill()
			srv.proc = nil
		}
		srv.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// session returns the live process for a request's Mcp-Session-Id, or nil.
func (s *mcpServer) session(r *http.Request) *mcpProc {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proc == nil || s.proc.exited() || r.Header.Get("Mcp-Session-Id") != s.proc.session {
		return nil
	}
	return s.proc
}

func (g *MCPGateway) post(w http.ResponseWriter, r *http.Request, srv *mcpServer) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		httpRPCError(w, http.StatusBadRequest, "cannot read body")
		return
	}
	body = bytes.TrimSpace(body)
	var msgs []json.RawMessage
	batch := len(body) > 0 && body[0] == '['
	if batch {
		err = json.Unmarshal(body, &msgs)
	} else {
		msgs = []json.RawMessage{body}
	}
	if err != nil || len(msgs) == 0 {
		httpRPCError(w, http.StatusBadRequest, "body must be a JSON-RPC message")
		return
	}

	var responses [][]byte
	var sessionHeader string
	for _, raw := range msgs {
		var m rpcMsg
		if err := json.Unmarshal(raw, &m); err != nil {
			responses = append(responses, rpcError(json.RawMessage("null"), -32700, "parse error"))
			continue
		}
		if m.Method == "initialize" {
			p, err := g.start(srv)
			if err != nil {
				responses = append(responses, rpcError(m.ID, -32000, "cannot start MCP server "+srv.spec.Name+": "+err.Error()))
				continue
			}
			sessionHeader = p.session
		}
		p := srv.session(r)
		if p == nil && sessionHeader != "" {
			srv.mu.Lock()
			p = srv.proc
			srv.mu.Unlock()
		}
		if p == nil {
			// Unknown or expired session: the client re-initializes (MCP
			// streamable HTTP transport).
			httpRPCError(w, http.StatusNotFound, "no MCP session; send initialize")
			return
		}
		if !m.isRequest() {
			// Notification, or a response to a server-initiated request.
			p.write(raw)
			continue
		}
		if resp := g.enforce(srv, &m); resp != nil {
			responses = append(responses, resp)
			continue
		}
		resp, err := p.call(r.Context(), m.ID, raw)
		if err != nil {
			responses = append(responses, rpcError(m.ID, -32000, err.Error()))
			continue
		}
		if m.Method == "tools/list" {
			resp = g.filterTools(srv, resp)
		}
		responses = append(responses, resp)
	}

	if sessionHeader != "" {
		w.Header().Set("Mcp-Session-Id", sessionHeader)
	}
	if len(responses) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if batch {
		w.Write([]byte("["))
		w.Write(bytes.Join(responses, []byte(",")))
		w.Write([]byte("]"))
		return
	}
	w.Write(responses[0])
}

// enforce decides a client request; a non-nil result is the answer, sent
// instead of forwarding.
func (g *MCPGateway) enforce(srv *mcpServer, m *rpcMsg) []byte {
	eff := g.effective(srv.run.runID)
	switch m.Method {
	case "tools/call":
		var p struct {
			Name string `json:"name"`
		}
		json.Unmarshal(m.Params, &p)
		d := decideMCP(eff, policy.MCPRequest{Kind: "tool", Server: srv.spec.Name, Argv: srv.spec.Command, Tool: p.Name})
		data := mcpData(srv.spec.Name, m.Method, p.Name, d)
		srv.mu.Lock()
		drifted := srv.drifted[p.Name]
		srv.mu.Unlock()
		if d.Allowed() && drifted && eff != nil && eff.Enforcing() {
			d.Action, d.Enforced = policy.ActionDeny, true
			d.Message = fmt.Sprintf("Tool %s on MCP server %s changed its definition since it was pinned; "+
				"it stays blocked until an operator re-approves it.", p.Name, srv.spec.Name)
			data = mcpData(srv.spec.Name, m.Method, p.Name, d)
			data.Reason = "tool definition changed since pinned"
		}
		g.record(srv.run, data)
		if !d.Allowed() {
			return toolDenied(m.ID, d.Message)
		}
	case "resources/read":
		var p struct {
			URI string `json:"uri"`
		}
		json.Unmarshal(m.Params, &p)
		d := decideMCP(eff, policy.MCPRequest{Kind: "resource", Server: srv.spec.Name, Argv: srv.spec.Command, URI: p.URI})
		g.record(srv.run, mcpData(srv.spec.Name, m.Method, p.URI, d))
		if !d.Allowed() {
			return rpcError(m.ID, -32002, d.Message)
		}
	}
	return nil
}

// filterTools removes tools the run may not call from a tools/list
// response, and pins definitions where the policy asks (design §8.4).
func (g *MCPGateway) filterTools(srv *mcpServer, resp []byte) []byte {
	var m map[string]json.RawMessage
	if json.Unmarshal(resp, &m) != nil || m["result"] == nil {
		return resp
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(m["result"], &result) != nil {
		return resp
	}
	var tools []json.RawMessage
	if json.Unmarshal(result["tools"], &tools) != nil {
		return resp
	}
	eff := g.effective(srv.run.runID)
	pin := eff != nil && eff.PinsToolDefinitions(srv.spec.Command)
	kept := tools[:0:0]
	for _, t := range tools {
		var head struct {
			Name string `json:"name"`
		}
		json.Unmarshal(t, &head)
		d := decideMCP(eff, policy.MCPRequest{Kind: "tool", Server: srv.spec.Name, Argv: srv.spec.Command, Tool: head.Name})
		if !d.Allowed() {
			continue // not offered: the model never sees a tool it cannot call
		}
		if pin && g.pins != nil {
			if changed, err := g.pins.Check(srv.pinKey(eff), head.Name, t); err != nil {
				log.Printf("mcp gateway: pin store: %v", err)
			} else if changed {
				srv.mu.Lock()
				srv.drifted[head.Name] = true
				srv.mu.Unlock()
				data := MCPData{Server: srv.spec.Name, Method: "tools/list", Name: head.Name, Reason: "tool definition changed since pinned"}
				if eff.Enforcing() {
					data.Decision, data.Enforced = policy.ActionDeny, true
					g.record(srv.run, data)
					continue
				}
				data.Decision = policy.ActionAllow
				data.WouldDeny = []string{"pin"}
				g.record(srv.run, data)
			}
		}
		kept = append(kept, t)
	}
	result["tools"], _ = json.Marshal(kept)
	m["result"], _ = json.Marshal(result)
	out, err := json.Marshal(m)
	if err != nil {
		return resp
	}
	return out
}

// pinKey identifies a server for pinning: the policy rule that governs
// it, so pins are shared by every run using that rule on this node.
func (s *mcpServer) pinKey(eff *policy.Effective) string {
	for _, l := range eff.Layers {
		if r := l.Profile.MCPServerRule(s.spec.Command); r != "" {
			return l.Profile.Name + "/" + r
		}
	}
	return "server/" + s.spec.Name
}

func (g *MCPGateway) stream(w http.ResponseWriter, r *http.Request, srv *mcpServer) {
	p := srv.session(r)
	if p == nil {
		httpRPCError(w, http.StatusNotFound, "no MCP session; send initialize")
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	for {
		select {
		case msg := <-p.out:
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
			fl.Flush()
		case <-r.Context().Done():
			return
		case <-p.done:
			return
		}
	}
}

// start (re)launches the server process for a new session.
func (g *MCPGateway) start(srv *mcpServer) (*mcpProc, error) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.proc != nil {
		srv.proc.kill()
		srv.proc = nil
	}
	p, err := g.spawn(srv)
	if err != nil {
		return nil, err
	}
	srv.proc = p
	return p, nil
}

// launchGoverned prepares the server as the run's user, spawned
// directly into a child cgroup of the run.
func (g *MCPGateway) launchGoverned(srv *mcpServer) (*exec.Cmd, func(), error) {
	run := srv.run
	cgPath := filepath.Join(run.cgPath, "mcp-"+srv.spec.Name)
	if err := os.Mkdir(cgPath, 0o755); err != nil && !os.IsExist(err) {
		return nil, nil, err
	}
	cgID, err := GetCgroupID(cgPath)
	if err != nil {
		return nil, nil, err
	}
	// Egress from the server is the run's: register its cgroup so the
	// proxy attributes it.
	g.api.addRunCgroup(run.runID, cgID)
	cgDir, err := os.Open(cgPath)
	if err != nil {
		return nil, nil, err
	}

	env := make([]string, 0, len(srv.spec.Env))
	for k, v := range srv.spec.Env {
		env = append(env, k+"="+v)
	}
	cmd := exec.Command(srv.spec.Command[0], srv.spec.Command[1:]...)
	cmd.Dir = run.cwd
	cmd.Env = env
	groups := make([]uint32, len(run.groups))
	for i, gid := range run.groups {
		groups[i] = uint32(gid)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential:  &syscall.Credential{Uid: uint32(run.uid), Gid: uint32(run.gid), Groups: groups},
		UseCgroupFD: true,
		CgroupFD:    int(cgDir.Fd()),
		Setsid:      true,
	}
	return cmd, func() { cgDir.Close() }, nil
}

func (g *MCPGateway) spawn(srv *mcpServer) (*mcpProc, error) {
	run := srv.run
	cmd, cleanup, err := g.launch(srv)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = &prefixLogger{prefix: fmt.Sprintf("mcp %s/%s: ", run.runID, srv.spec.Name)}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	var sid [16]byte
	rand.Read(sid[:])
	p := &mcpProc{
		g: g, srv: srv, cmd: cmd, stdin: stdin,
		session: hex.EncodeToString(sid[:]),
		pending: map[string]chan []byte{},
		out:     make(chan []byte, 256),
		done:    make(chan struct{}),
	}
	go p.readLoop(stdout)
	go func() {
		cmd.Wait()
		close(p.done)
	}()
	log.Printf("mcp gateway: run %s: started %s (pid %d) as uid %d", run.runID, srv.spec.Name, cmd.Process.Pid, run.uid)
	return p, nil
}

type prefixLogger struct {
	prefix string
	buf    []byte
}

func (l *prefixLogger) Write(b []byte) (int, error) {
	l.buf = append(l.buf, b...)
	for {
		i := bytes.IndexByte(l.buf, '\n')
		if i < 0 {
			if len(l.buf) > 4096 {
				l.buf = l.buf[:0]
			}
			return len(b), nil
		}
		log.Printf("%s%s", l.prefix, l.buf[:i])
		l.buf = l.buf[i+1:]
	}
}

// mcpProc is one running stdio server and its session.
type mcpProc struct {
	g       *MCPGateway
	srv     *mcpServer
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	wmu     sync.Mutex
	session string

	mu      sync.Mutex
	pending map[string]chan []byte
	out     chan []byte // server-initiated messages, for the GET stream
	done    chan struct{}
}

func (p *mcpProc) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (p *mcpProc) kill() {
	if p.cmd.Process != nil {
		p.cmd.Process.Kill()
	}
	p.stdin.Close()
}

func (p *mcpProc) write(msg []byte) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	if _, err := p.stdin.Write(append(bytes.TrimSpace(msg), '\n')); err != nil {
		return err
	}
	return nil
}

// call forwards a client request and waits for the server's response.
func (p *mcpProc) call(ctx context.Context, id json.RawMessage, raw []byte) ([]byte, error) {
	key := string(id)
	ch := make(chan []byte, 1)
	p.mu.Lock()
	p.pending[key] = ch
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.pending, key)
		p.mu.Unlock()
	}()
	if err := p.write(raw); err != nil {
		return nil, fmt.Errorf("MCP server %s is gone", p.srv.spec.Name)
	}
	select {
	case resp := <-ch:
		return resp, nil
	case <-p.done:
		return nil, fmt.Errorf("MCP server %s exited", p.srv.spec.Name)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *mcpProc) readLoop(stdout io.Reader) {
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		var m rpcMsg
		if json.Unmarshal(line, &m) != nil {
			continue // stdio servers must write only JSON-RPC to stdout
		}
		if m.isResponse() {
			p.mu.Lock()
			ch := p.pending[string(m.ID)]
			p.mu.Unlock()
			if ch != nil {
				ch <- line
			}
			continue
		}
		if m.Method == "sampling/createMessage" && m.isRequest() {
			// The sampling inversion (design §8.4): a server asking the
			// client to run the model.
			eff := p.g.effective(p.srv.run.runID)
			d := decideMCP(eff, policy.MCPRequest{Kind: "sampling", Server: p.srv.spec.Name, Argv: p.srv.spec.Command})
			if eff == nil {
				d = policy.EffectiveDecision{Decision: policy.Decision{Action: policy.ActionAllow}}
			}
			p.g.record(p.srv.run, mcpData(p.srv.spec.Name, m.Method, "", d))
			if !d.Allowed() {
				p.write(rpcError(m.ID, -32001, d.Message))
				continue
			}
		}
		select {
		case p.out <- line:
		default: // no GET stream draining it; drop rather than block
		}
	}
}

// PinStore keeps tool-definition hashes across runs (design §8.4), so a
// server that changes a tool after review is caught.
type PinStore struct {
	path string
	mu   sync.Mutex
	pins map[string]map[string]string // server key -> tool -> sha256
}

// OpenPinStore loads (or starts) the store at path.
func OpenPinStore(path string) (*PinStore, error) {
	ps := &PinStore{path: path, pins: map[string]map[string]string{}}
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &ps.pins); err != nil {
			return nil, fmt.Errorf("pin store %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return ps, nil
}

// canonicalHash hashes a tool definition independent of key order and
// whitespace.
func canonicalHash(def json.RawMessage) (string, error) {
	var v interface{}
	if err := json.Unmarshal(def, &v); err != nil {
		return "", err
	}
	b, err := json.Marshal(v) // map keys are sorted
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Check pins a tool definition on first sight and reports whether it
// differs from the pinned one.
func (ps *PinStore) Check(server, tool string, def json.RawMessage) (changed bool, err error) {
	h, err := canonicalHash(def)
	if err != nil {
		return false, err
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.pins[server] == nil {
		ps.pins[server] = map[string]string{}
	}
	switch prev, ok := ps.pins[server][tool]; {
	case !ok:
		ps.pins[server][tool] = h
		data, _ := json.MarshalIndent(ps.pins, "", "  ")
		if err := os.MkdirAll(filepath.Dir(ps.path), 0o755); err != nil {
			return false, err
		}
		return false, writeFileAtomic(ps.path, data, 0o600)
	default:
		return prev != h, nil
	}
}
