// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build !bcc
// +build !bcc

package clovisor

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// NodeAgent is the main daemon for node-level agent egress tracking
type NodeAgent struct {
	cmgr       *CgroupManager
	audit      *AgentAudit
	bpfReader  *EBPFReader
	recorder   *RunRecorder
	api        *RunAPIServer
	extproc    *ExtProcServer
	proxyOpts  *NodeAgentOptions
	ca         *NodeCA
	terminated []string // patterns in the bootstrap last written
	mcp        *MCPGateway
	httpEvents chan AuditEvent
	policyDir  string
	stopChan   chan bool
	handled    chan struct{} // closed when handleEvents has drained
	running    bool
}

// NodeAgentOptions configures where run timelines go.
type NodeAgentOptions struct {
	// Identity is how the proxy and the MCP gateway know a run: "cgroup"
	// (Linux; kernel audit and enforcement-grade identity) or
	// "credential" (anywhere; a per-run secret in the proxy URL, which is
	// a claim, design §4.3). Empty means cgroup on Linux, credential
	// elsewhere.
	Identity string
	// Dirs holds sockets, generated files and state; DefaultDirs() if
	// empty. Paths below left empty are derived from it.
	Dirs Dirs

	BPFObjPath string
	OutDir     string // finished timelines; DefaultRunOutDir if empty
	SocketPath string // run API socket; DefaultRunAPISocket if empty
	// PolicyDir holds profiles and ceilings. If it does not exist, runs
	// are unprofiled, as in Phase 1.
	PolicyDir string

	// ProxyListen enables the explicit proxy (milestone 2.3): the node
	// agent serves ext_proc and writes an Envoy bootstrap that listens
	// here. Leave invalid to run without a proxy.
	ProxyListen   netip.AddrPort
	ExtProcSocket string   // DefaultExtProcSocket if empty
	EnvoyAdmin    string   // Envoy admin socket; /run/clovisor/envoy/admin.sock if empty
	EnvoyConfig   string   // where to write the bootstrap; /run/clovisor/envoy.json if empty
	EnvoyUIDs     []uint32 // uids Envoy runs as, admitted to ext_proc (root always is)
	// NonRunProxy lets processes outside any run use the proxy.
	NonRunProxy bool

	// CADir holds the node CA used for termination; /var/lib/clovisor/ca if empty.
	CADir string
	// EnvoyUpstreamCA is the system trust store as Envoy sees it, used to
	// verify origins behind termination.
	EnvoyUpstreamCA string

	// MCPListen enables the local MCP gateway on a loopback address.
	MCPListen netip.AddrPort
	// MCPPins is the tool-definition pin store; /var/lib/clovisor/mcp-pins.json if empty.
	MCPPins string
}

// NewNodeAgent creates a new node agent
func NewNodeAgent() (*NodeAgent, error) {
	cmgr, err := NewCgroupManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create cgroup manager: %w", err)
	}

	audit, err := NewAgentAudit()
	if err != nil {
		return nil, fmt.Errorf("failed to create agent audit: %w", err)
	}

	na := &NodeAgent{
		cmgr:     cmgr,
		audit:    audit,
		stopChan: make(chan bool),
		running:  false,
	}

	return na, nil
}

// NewNodeAgentWithBPF creates a node agent; see NewNodeAgentFromOptions.
func NewNodeAgentWithBPF(opts NodeAgentOptions) (*NodeAgent, error) {
	return NewNodeAgentFromOptions(opts)
}

// NewNodeAgentFromOptions creates a node agent. With cgroup identity it
// loads and attaches the audit BPF program, scoped to the agents cgroup
// subtree; with credential identity it needs no kernel features and no
// root. Either way it writes one timeline per run.
func NewNodeAgentFromOptions(opts NodeAgentOptions) (*NodeAgent, error) {
	if opts.Dirs == (Dirs{}) {
		opts.Dirs = DefaultDirs()
	}
	switch opts.Identity {
	case "":
		opts.Identity = "credential"
		if runtime.GOOS == "linux" {
			opts.Identity = "cgroup"
		}
	case "cgroup":
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("cgroup identity needs Linux; use credential identity")
		}
	case "credential":
	default:
		return nil, fmt.Errorf("identity must be cgroup or credential, not %q", opts.Identity)
	}
	credential := opts.Identity == "credential"
	d := opts.Dirs
	if opts.OutDir == "" {
		opts.OutDir = d.Runs()
	}
	if opts.SocketPath == "" {
		opts.SocketPath = d.APISocket()
	}
	if opts.PolicyDir == "" {
		opts.PolicyDir = DefaultPolicyDir
	}
	// Load policy before touching the kernel or the socket: a policy that
	// does not load is fatal, and failing here leaves nothing behind.
	set, err := loadNodePolicy(opts.PolicyDir, !credential)
	if err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 {
		fmt.Printf("identity: %s; the node agent runs as uid %d, so the user can stop it or edit its files: policy is advisory\n",
			opts.Identity, os.Geteuid())
	} else {
		fmt.Printf("identity: %s\n", opts.Identity)
	}

	registry := NewRunRegistry()
	httpEvents := make(chan AuditEvent, 1000)
	var cmgr *CgroupManager
	var audit *AgentAudit
	var recorder *RunRecorder
	agentsDir := ""
	if credential {
		if audit, err = NewAgentAudit(); err != nil {
			return nil, err
		}
		if recorder, err = NewCredentialRunRecorder(opts.OutDir, registry); err != nil {
			return nil, err
		}
	} else {
		if cmgr, err = NewCgroupManager(); err != nil {
			return nil, fmt.Errorf("failed to create cgroup manager: %w", err)
		}
		agentsDir = cmgr.GetAgentsDir()
		agentsID, err := GetCgroupID(agentsDir)
		if err != nil {
			return nil, fmt.Errorf("failed to read agents cgroup id: %w", err)
		}
		level, err := cgroupLevel(agentsDir)
		if err != nil {
			return nil, err
		}
		if recorder, err = NewRunRecorder(agentsDir, opts.OutDir, registry); err != nil {
			return nil, err
		}
		if audit, err = NewAgentAuditWithBPF(opts.BPFObjPath, agentsDir, agentsID, level); err != nil {
			return nil, fmt.Errorf("failed to create agent audit: %w", err)
		}
	}
	closeAudit := func() {
		if audit.reader != nil {
			audit.reader.Close()
		}
	}

	// Listen only once BPF is attached, so no run can start unobserved.
	api, err := NewRunAPIServer(opts.SocketPath, cmgr, registry)
	if err != nil {
		closeAudit()
		return nil, err
	}
	if credential {
		api.Events = httpEvents
	}
	if set != nil {
		api.SetPolicy(set)
	}

	var xp *ExtProcServer
	var proxyCA *NodeCA
	var proxyTerminated []string
	if opts.ProxyListen.IsValid() {
		if opts.ExtProcSocket == "" {
			opts.ExtProcSocket = d.ExtProcSocket()
		}
		if opts.EnvoyAdmin == "" {
			// In a directory only Envoy can use, since Envoy creates the
			// socket and must not be able to touch anything else here.
			dir := d.EnvoyDir()
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, err
			}
			if len(opts.EnvoyUIDs) > 0 {
				if err := os.Chown(dir, int(opts.EnvoyUIDs[0]), -1); err != nil {
					return nil, err
				}
			}
			opts.EnvoyAdmin = dir + "/admin.sock"
		}
		if opts.EnvoyConfig == "" {
			opts.EnvoyConfig = d.EnvoyConfig()
		}
		if opts.CADir == "" {
			opts.CADir = d.CADir()
		}
		if opts.EnvoyUpstreamCA == "" {
			opts.EnvoyUpstreamCA = systemUpstreamCA()
		}
		ca, err := LoadOrCreateCA(opts.CADir)
		if err == nil {
			err = writeTrust(ca, d)
		}
		var terminated []string
		if err == nil {
			terminated, err = writeEnvoyConfig(opts, ca, set)
		}
		if err != nil {
			api.Close()
			closeAudit()
			return nil, fmt.Errorf("envoy bootstrap: %w", err)
		}
		proxyCA, proxyTerminated = ca, terminated
		api.TrustBundle, api.NodeCACert = d.TrustBundle(), d.NodeCACert()
		xp = NewExtProcServer(api, agentsDir, httpEvents)
		if xp.Pins, err = openPins(&opts); err != nil {
			api.Close()
			closeAudit()
			return nil, err
		}
		api.Pins = xp.Pins
		xp.NonRunAllowed = opts.NonRunProxy
		if err := xp.Listen(opts.ExtProcSocket, opts.EnvoyUIDs); err != nil {
			api.Close()
			closeAudit()
			return nil, err
		}
		api.ProxyURL = "http://" + opts.ProxyListen.String()
		recorder.ProxyAddrs = map[string]bool{opts.ProxyListen.String(): true}
		fmt.Printf("proxy: ext_proc on %s; Envoy bootstrap %s (proxy %s)\n", opts.ExtProcSocket, opts.EnvoyConfig, opts.ProxyListen)
	}

	var gw *MCPGateway
	if opts.MCPListen.IsValid() {
		if !opts.MCPListen.Addr().IsLoopback() {
			return nil, fmt.Errorf("the MCP gateway must listen on loopback, not %s", opts.MCPListen)
		}
		pins, err := openPins(&opts)
		if err != nil {
			return nil, err
		}
		api.Pins = pins
		if gw, err = NewMCPGateway(api, opts.MCPListen, pins, httpEvents); err != nil {
			return nil, err
		}
		api.MCP = gw
		fmt.Printf("mcp: gateway on http://%s/mcp/<server>; pins in %s\n", opts.MCPListen, opts.MCPPins)
	}

	na := &NodeAgent{
		mcp:        gw,
		ca:         proxyCA,
		terminated: proxyTerminated,
		cmgr:       cmgr,
		audit:      audit,
		recorder:   recorder,
		api:        api,
		extproc:    xp,
		httpEvents: httpEvents,
		policyDir:  opts.PolicyDir,
		stopChan:   make(chan bool),
		running:    false,
	}
	if xp != nil {
		o := opts
		na.proxyOpts = &o
	}

	return na, nil
}

// ReloadPolicy (re)loads the policy directory. On failure the policy in
// force stays, so a bad edit never leaves the node without policy; runs
// already bound keep their versions either way.
func (na *NodeAgent) ReloadPolicy() error {
	set, err := loadNodePolicy(na.policyDir, na.cmgr != nil)
	if err != nil {
		return err
	}
	if set != nil {
		na.api.SetPolicy(set)
	}
	if na.proxyOpts != nil {
		terminated, err := writeEnvoyConfig(*na.proxyOpts, na.ca, set)
		if err != nil {
			return fmt.Errorf("policy loaded, but the Envoy bootstrap could not be rewritten: %w", err)
		}
		if strings.Join(terminated, ",") != strings.Join(na.terminated, ",") {
			// ext_proc follows the route Envoy actually took, so until
			// Envoy restarts, newly terminated hosts' path rules are
			// refused rather than skipped.
			fmt.Printf("proxy: termination set is now [%s]; restart Envoy to apply it\n", strings.Join(terminated, ", "))
			na.terminated = terminated
		}
	}
	return nil
}

var (
	pinsOnce *PinStore
	pinsPath string
)

// openPins opens the node's one pin store, shared by the MCP gateway
// (local servers) and ext_proc (remote servers).
func openPins(opts *NodeAgentOptions) (*PinStore, error) {
	if opts.MCPPins == "" {
		opts.MCPPins = opts.Dirs.Pins()
	}
	if pinsOnce != nil && pinsPath == opts.MCPPins {
		return pinsOnce, nil
	}
	ps, err := OpenPinStore(opts.MCPPins)
	if err != nil {
		return nil, err
	}
	pinsOnce, pinsPath = ps, opts.MCPPins
	return ps, nil
}

// writeTrust publishes the node's trust anchors for runs: the system
// roots plus the node CA, and the node CA alone.
func writeTrust(ca *NodeCA, d Dirs) error {
	bundle, err := ca.TrustBundle()
	if err != nil {
		return err
	}
	if err := writeFileAtomic(d.TrustBundle(), append(bundle, '\n'), 0o644); err != nil {
		return err
	}
	return writeFileAtomic(d.NodeCACert(), ca.CertPEM, 0o644)
}

// terminationSet is the node-wide set of patterns whose rules need
// termination (design §6.6), from the compiled posture.
func terminationSet(set *policy.Set) []string {
	if set == nil {
		return nil
	}
	var out []string
	for _, d := range set.Compiled.Posture {
		if d.Posture == policy.PostureTerminate {
			out = append(out, d.Dest)
		}
	}
	return out
}

// writeEnvoyConfig issues leaves for the termination set into Envoy's
// private directory and writes the bootstrap.
func writeEnvoyConfig(opts NodeAgentOptions, ca *NodeCA, set *policy.Set) ([]string, error) {
	patterns := terminationSet(set)
	tlsDir := filepath.Join(filepath.Dir(opts.EnvoyAdmin), "tls")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		return nil, err
	}
	envoyUID := -1
	if len(opts.EnvoyUIDs) > 0 {
		envoyUID = int(opts.EnvoyUIDs[0])
	}
	if err := os.Chown(tlsDir, envoyUID, -1); err != nil {
		return nil, err
	}
	var hosts []TerminatedHost
	for i, p := range patterns {
		certPEM, keyPEM, err := ca.Issue(p)
		if err != nil {
			return nil, err
		}
		th := TerminatedHost{Pattern: p, CertPath: filepath.Join(tlsDir, fmt.Sprintf("%d.crt", i)), KeyPath: filepath.Join(tlsDir, fmt.Sprintf("%d.key", i))}
		if err := writeFileAtomicOwned(th.CertPath, certPEM, 0o600, envoyUID); err != nil {
			return nil, err
		}
		if err := writeFileAtomicOwned(th.KeyPath, keyPEM, 0o600, envoyUID); err != nil {
			return nil, err
		}
		hosts = append(hosts, th)
	}
	boot, err := EnvoyBootstrap(EnvoyConfig{ProxyListen: opts.ProxyListen, ExtProcSocket: opts.ExtProcSocket,
		AdminSocket: opts.EnvoyAdmin, Terminate: hosts, UpstreamCA: opts.EnvoyUpstreamCA})
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(opts.EnvoyConfig, boot, 0o644); err != nil {
		return nil, err
	}
	if len(patterns) > 0 {
		fmt.Printf("proxy: terminating TLS for %s\n", strings.Join(patterns, ", "))
	}
	return patterns, nil
}

// loadNodePolicy loads dir, or returns nil if it does not exist.
// loadNodePolicy loads the policy directory. A root node agent requires
// it to be root-owned. kernelIdentity says runs are known by cgroup,
// which the receipt reports as enforcement-grade identity.
func loadNodePolicy(dir string, kernelIdentity bool) (*policy.Set, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		fmt.Printf("policy: %s does not exist; runs are unprofiled\n", dir)
		return nil, nil
	}
	set, err := LoadPolicyDir(dir, policy.Options{Mode: policy.ExplicitProxy, Linux: kernelIdentity}, os.Geteuid() == 0)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, p := range set.Compiled.Profiles {
		names = append(names, p.Name+"@"+p.Profile.ShortVersion())
	}
	fmt.Printf("policy: loaded %s: %s\n", dir, strings.Join(names, ", "))
	return set, nil
}

// cgroupLevel returns the depth of path below the cgroup v2 root, as used
// by bpf_get_current_ancestor_cgroup_id (root is level 0).
func cgroupLevel(path string) (uint32, error) {
	rel, err := filepath.Rel(CgroupV2Root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return 0, fmt.Errorf("%s is not under %s", path, CgroupV2Root)
	}
	if rel == "." {
		return 0, nil
	}
	return uint32(len(strings.Split(rel, string(filepath.Separator)))), nil
}

// Start begins the node agent
func (na *NodeAgent) Start() error {
	if na.running {
		return fmt.Errorf("node agent already running")
	}

	// Start the audit event collection
	if err := na.audit.Start(); err != nil {
		return fmt.Errorf("failed to start audit: %w", err)
	}

	na.running = true
	fmt.Println("Node agent started")

	return nil
}

// Stop stops the node agent
func (na *NodeAgent) Stop() error {
	if !na.running {
		return fmt.Errorf("node agent not running")
	}

	// Stop serving first: runs ending now still get their rmdir events
	// recorded below. Runs still going are left running.
	if na.extproc != nil {
		na.extproc.Close()
	}
	if na.mcp != nil {
		na.mcp.Close()
	}
	if na.api != nil {
		na.api.Close()
	}

	// Close BPF reader if it exists
	if na.bpfReader != nil {
		na.bpfReader.Close()
		na.bpfReader = nil
	}

	// Stop the audit; this closes the event channel, so handleEvents
	// drains what is left and flushes runs still in progress.
	if err := na.audit.Stop(); err != nil {
		return fmt.Errorf("failed to stop audit: %w", err)
	}
	if na.handled != nil {
		<-na.handled
	}

	na.running = false
	fmt.Println("Node agent stopped")

	return nil
}

// Run starts the main event loop
func (na *NodeAgent) Run() error {
	if err := na.Start(); err != nil {
		return err
	}

	// Set up event handler
	na.handled = make(chan struct{})
	go na.handleEvents()
	if na.api != nil {
		go na.api.Serve()
	}
	if na.extproc != nil {
		go func() {
			if err := na.extproc.Serve(); err != nil {
				fmt.Fprintf(os.Stderr, "ext_proc: %v\n", err)
			}
		}()
	}
	if na.mcp != nil {
		go func() {
			if err := na.mcp.Serve(); err != nil {
				fmt.Fprintf(os.Stderr, "mcp gateway: %v\n", err)
			}
		}()
	}

	// Block forever - this is a daemon
	select {}
}

// handleEvents processes audit events
func (na *NodeAgent) handleEvents() {
	defer close(na.handled)
	// One goroutine feeds the recorder: kernel events and proxy decisions.
	events := na.audit.Events()
	for {
		select {
		case event, ok := <-events:
			if !ok {
				for {
					select {
					case ev := <-na.httpEvents:
						na.processEvent(ev)
						continue
					default:
					}
					break
				}
				goto flush
			}
			na.processEvent(event)
		case ev := <-na.httpEvents:
			na.processEvent(ev)
		}
	}
flush:
	if na.recorder != nil {
		for _, err := range na.recorder.Flush() {
			fmt.Fprintf(os.Stderr, "node agent: %v\n", err)
		}
	}
}

// Stop signals the node agent to stop
func (na *NodeAgent) StopSignal() {
	close(na.stopChan)
}

// processEvent logs a single audit event and records it in its run.
func (na *NodeAgent) processEvent(event AuditEvent) {
	ts := event.Timestamp.Format(time.RFC3339Nano)
	switch event.Type {
	case EventExec:
		d := event.Data.(ExecData)
		fmt.Printf("%s [EXEC] run=%d cgroup=%d pid=%d ppid=%d binary=%s args=%q\n",
			ts, event.RunCgroupID, event.CgroupID, event.PID, d.PPID, d.BinaryPath, d.Args)
	case EventConnect:
		d := event.Data.(ConnectData)
		fmt.Printf("%s [CONNECT] run=%d cgroup=%d pid=%d proto=%s dst=%s\n",
			ts, event.RunCgroupID, event.CgroupID, event.PID, d.Protocol,
			net.JoinHostPort(d.DstIP, strconv.Itoa(int(d.DstPort))))
	case EventDNS:
		d := event.Data.(DNSData)
		fmt.Printf("%s [DNS] run=%d cgroup=%d server=%s query=%s %s rcode=%s addrs=%v\n",
			ts, event.RunCgroupID, event.CgroupID, d.Server, d.Query, d.QType, d.RCode, d.Addrs())
	case EventMCP:
		d := event.Data.(MCPData)
		extra := ""
		if d.Layer != "" {
			extra += " layer=" + d.Layer
		}
		if len(d.WouldDeny) > 0 {
			extra += " would-deny=" + strings.Join(d.WouldDeny, ",")
		}
		if d.Reason != "" {
			extra += " reason=" + strconv.Quote(d.Reason)
		}
		fmt.Printf("%s [MCP] run=%d %s %s %s decision=%s%s\n", ts, event.RunCgroupID, d.Server, d.Method, d.Name, d.Decision, extra)
	case EventHTTP:
		d := event.Data.(HTTPData)
		what := d.Method + " " + net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port))) + d.Path
		extra := ""
		if d.Rule != "" {
			extra += " rule=" + d.Rule
		}
		if d.Layer != "" {
			extra += " layer=" + d.Layer
		}
		if len(d.WouldDeny) > 0 {
			extra += " would-deny=" + strings.Join(d.WouldDeny, ",")
		}
		if d.Reason != "" {
			extra += " reason=" + strconv.Quote(d.Reason)
		}
		fmt.Printf("%s [HTTP] run=%d %s decision=%s%s\n", ts, event.RunCgroupID, what, d.Decision, extra)
	case EventRunStart:
		fmt.Printf("%s [RUN START] run=%d path=%s\n", ts, event.RunCgroupID, event.Data.(RunData).CgroupPath)
	case EventRunEnd:
		fmt.Printf("%s [RUN END] run=%d path=%s\n", ts, event.RunCgroupID, event.Data.(RunData).CgroupPath)
	}

	if na.recorder == nil {
		return
	}
	tl, err := na.recorder.Handle(event)
	if err != nil {
		fmt.Fprintf(os.Stderr, "node agent: %v\n", err)
		return
	}
	if tl != nil {
		fmt.Printf("%s [TIMELINE] run %s: %d execs, %d connects, %d dns, complete=%t -> %s\n",
			ts, tl.RunID, tl.Summary.Execs, tl.Summary.Connects, tl.Summary.DNSReplies, tl.Complete,
			TimelinePath(na.recorder.OutDir, tl.RunID))
	}
}
