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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
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
	resolver   *Resolver
	envoy      atomic.Value // EnvoyState
	gateWhy    atomic.Value // string: why the proxy is not gated
	identity   string
	httpEvents chan AuditEvent
	policyDir  string
	deployment policy.DeploymentMode
	lsm        bool
	quic       bool
	execHash   bool // the kernel's exec hook hashes files (milestone 5.7)
	uprobes    bool // TLS plaintext capture (milestone 6.2)
	restored   RestoreReport
	tlsParser  *tlsParser        // TLS plaintext (milestone 6.2)
	tlsStacks  map[uint32]string // a probed process's own TLS stack, as its records name it (milestones 6.3, 6.4)
	tlsLibs    []string
	relay      *QUICRelay
	stopChan   chan bool
	handled    chan struct{} // closed when handleEvents has drained
	running    bool
	limiter    *Limiter
	limitDone  chan struct{}
}

// NodeAgentOptions configures where run timelines go.
type NodeAgentOptions struct {
	// Identity is how the proxy and the MCP gateway know a run: "cgroup"
	// (Linux; kernel audit and enforcement-grade identity) or
	// "credential" (anywhere; a per-run secret in the proxy URL, which is
	// a claim, design §4.3) or "actor" (Agent Substrate Actors, known by
	// their mTLS certificates and checked against Substrate, milestone
	// 7.3), or "substrate" (Actors behind Substrate's egress gateway,
	// whose Envoy calls ext_proc on Gateway, milestone 7.4). Empty means
	// cgroup on Linux, credential elsewhere.
	Identity string
	// Gateway is the ext_proc listener for Substrate's gateway.
	Gateway GatewayTLS
	// Actor identity: the Actor CA, the proxy listener's own certificate
	// (Actors connect to it over TLS), the SPIFFE trust domain
	// (DefaultActorTrustDomain if empty), Substrate's API, and how often
	// live Actors are checked (DefaultActorCheck if 0).
	ActorCA          string
	ActorProxyCert   string
	ActorProxyKey    string
	ActorTrustDomain string
	Substrate        SubstrateOptions
	ActorCheck       time.Duration
	// Dirs holds sockets, generated files and state; DefaultDirs() if
	// empty. Paths below left empty are derived from it.
	Dirs Dirs

	BPFObjPath string
	// AgentsCgroup names the cgroup runs live under, below the cgroup
	// root; AgentsSubdir if empty.
	AgentsCgroup string
	OutDir       string // finished timelines; DefaultRunOutDir if empty
	SocketPath   string // run API socket; DefaultRunAPISocket if empty
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
	// MaxInspectBody is the largest request body the proxy checks for
	// content rules or remote MCP (milestone 5.1); larger ones are
	// refused. Zero means DefaultMaxBody.
	MaxInspectBody int

	// CADir holds the node CA used for termination; /var/lib/clovisor/ca if empty.
	CADir string
	// EnvoyUpstreamCA is the system trust store as Envoy sees it, used to
	// verify origins behind termination.
	EnvoyUpstreamCA string

	// Transparent configures redirect-or-deny (milestone 3.1): every TCP
	// connect from a run goes to Envoy's transparent listener, or is
	// refused. Needs cgroup identity and the proxy. Its exceptions are
	// filled in from ProxyListen and MCPListen.
	Transparent TransparentOptions
	// DNSUpstreams are where the local resolver forwards allowed queries
	// ("ip:port"); the host's /etc/resolv.conf nameservers if empty.
	DNSUpstreams []string

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
	case "actor":
		switch {
		case !opts.ProxyListen.IsValid():
			return nil, fmt.Errorf("Actor identity needs the proxy (-proxy-listen): Actors are known only there")
		case opts.ActorCA == "" || opts.ActorProxyCert == "" || opts.ActorProxyKey == "":
			return nil, fmt.Errorf("Actor identity needs the Actor CA and the proxy's certificate and key (-actor-ca, -actor-proxy-cert, -actor-proxy-key)")
		case opts.MCPListen.IsValid():
			return nil, fmt.Errorf("the MCP gateway does not know Actors yet: leave -mcp-listen unset with Actor identity")
		}
	case "substrate":
		switch {
		case !opts.Gateway.Addr.IsValid():
			return nil, fmt.Errorf("Substrate identity needs the ext_proc listener for its gateway (-gateway-listen)")
		case opts.ProxyListen.IsValid() || opts.MCPListen.IsValid():
			return nil, fmt.Errorf("behind Substrate's gateway Clovisor has no proxy or MCP gateway of its own: leave -proxy-listen and -mcp-listen unset")
		}
	default:
		return nil, fmt.Errorf("identity must be cgroup, credential, actor or substrate, not %q", opts.Identity)
	}
	gateway := opts.Identity == "substrate"
	actor := opts.Identity == "actor" || gateway
	// Actor identity has no kernel part either: what follows treats it as
	// credential identity does, except where it says otherwise.
	credential := opts.Identity == "credential" || actor
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
	t := &opts.Transparent
	if err := t.normalize(); err != nil {
		return nil, err
	}
	if t.Mode != TransparentOff {
		if credential {
			return nil, fmt.Errorf("transparent mode needs cgroup identity")
		}
		if !opts.ProxyListen.IsValid() {
			return nil, fmt.Errorf("transparent mode needs the proxy (-proxy-listen)")
		}
	}
	// Runs reach the explicit proxy and the MCP gateway directly. The
	// connect hooks use this list only in transparent mode; the egress
	// byte count, in every mode, counts loopback bytes to them.
	t.Exceptions = nil
	for _, a := range []netip.AddrPort{opts.ProxyListen, opts.MCPListen} {
		if a.IsValid() {
			t.Exceptions = append(t.Exceptions, a)
		}
	}
	// Load policy before touching the kernel or the socket: a policy that
	// does not load is fatal, and failing here leaves nothing behind.
	quic := t.QUICPort != 0
	lsm := lsmFor(*t, credential)
	// Whether exec.allow hashes can be verified decides how profiles
	// compile, so it is probed before they load.
	t.ExecHash = lsm && ExecHashSupported(opts.BPFObjPath)
	if t.TLSCapture && credential {
		return nil, fmt.Errorf("-uprobes needs cgroup identity: probes are attached to a run's processes")
	}
	set, err := loadNodePolicy(opts.PolicyDir, !credential, actor, t.DeploymentMode(), lsm, quic, t.ExecHash, t.TLSCapture)
	if err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 && !gateway {
		fmt.Printf("identity: %s; the node agent runs as uid %d, so the user can stop it or edit its files: policy is advisory\n",
			opts.Identity, os.Geteuid())
	} else {
		fmt.Printf("identity: %s\n", opts.Identity)
	}

	registry := NewRunRegistry()
	httpEvents := make(chan AuditEvent, 1000)
	// The resolver's sockets exist before the hooks send DNS to them, so
	// queries arriving during start-up wait instead of being refused.
	var resolver *Resolver
	if t.Mode != TransparentOff {
		if resolver, err = NewResolver(nil, "", t.DNSPort, opts.DNSUpstreams, t.Mode == TransparentEnforce, httpEvents); err != nil {
			return nil, fmt.Errorf("resolver: %w", err)
		}
	}
	// Likewise the QUIC relay's (milestone 5.6); it decides once ext_proc
	// exists.
	var relay *QUICRelay
	if quic {
		if credential || !opts.ProxyListen.IsValid() {
			return nil, fmt.Errorf("-quic needs cgroup identity, the proxy and transparent enforce mode")
		}
		if relay, err = NewQUICRelay(nil, t.QUICPort); err != nil {
			if resolver != nil {
				resolver.Close()
			}
			return nil, err
		}
	}
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
		name := opts.AgentsCgroup
		if name == "" {
			name = AgentsSubdir
		}
		if cmgr, err = NewCgroupManagerNamed(name); err != nil {
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
		// Runs that outlived the previous node agent (milestone 6.1): no
		// heartbeat, so their connects are refused, until they have their
		// grants back.
		if n, err := PendingGrants(d.Grants()); err != nil {
			return nil, fmt.Errorf("grants: %w (move it aside to start anyway: the runs it lists then come back unprofiled)", err)
		} else if n > 0 && t.Mode != TransparentOff {
			t.DeferBeat = true
		}
		if audit, err = NewAgentAuditWithBPF(opts.BPFObjPath, agentsDir, agentsID, level, opts.Transparent); err != nil {
			return nil, fmt.Errorf("failed to create agent audit: %w", err)
		}
	}
	closeAudit := func() {
		if audit.reader != nil {
			audit.reader.Close()
		}
		if resolver != nil {
			resolver.Close()
		}
		if relay != nil {
			relay.Close()
		}
	}

	// Listen only once BPF is attached, so no run can start unobserved.
	api, err := NewRunAPIServer(opts.SocketPath, cmgr, registry)
	if err != nil {
		closeAudit()
		return nil, err
	}
	// With cgroup identity only sessions, which have no cgroup, report
	// their start and end this way.
	api.Events = httpEvents
	if !credential {
		api.GrantsPath = d.Grants()
	}
	api.Transparent = opts.Transparent.Mode
	if resolver != nil {
		resolver.api, resolver.agentsDir = api, agentsDir
		fmt.Printf("dns: resolver on 127.0.0.1:%d and [::1]:%d, forwarding to %s\n", t.DNSPort, t.DNSPort, strings.Join(resolver.upstreams, ", "))
	}
	if set != nil {
		api.SetPolicy(set)
	}
	var actors *ActorVerifier
	var directory ActorDirectory
	if actor {
		if !gateway {
			actors, err = NewActorVerifier(opts.ActorCA, opts.ActorTrustDomain)
		}
		if err == nil {
			so := opts.Substrate
			if gateway && so.Timeout == 0 {
				// Substrate's gateway waits 2s for each answer.
				so.Timeout = SubstrateGatewayAPITimeout
			}
			directory, err = DialSubstrate(so)
		}
		if err != nil {
			api.Close()
			closeAudit()
			return nil, fmt.Errorf("Actor identity: %w", err)
		}
		api.EnableActors(directory, opts.ActorCheck)
		if gateway {
			fmt.Printf("actors: as Substrate's gateway verified them; Substrate's API at %s\n", opts.Substrate.Addr)
		} else {
			fmt.Printf("actors: certificates from %s (trust domain %s); Substrate's API at %s\n", opts.ActorCA, actors.TrustDomain, opts.Substrate.Addr)
		}
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
		xp.Actors, xp.Directory = actors, directory
		xp.MaxBody = opts.MaxInspectBody
		if err := xp.Listen(opts.ExtProcSocket, opts.EnvoyUIDs); err != nil {
			api.Close()
			closeAudit()
			return nil, err
		}
		api.ProxyURL = "http://" + opts.ProxyListen.String()
		if actor {
			api.ProxyURL = "https://" + opts.ProxyListen.String()
		}
		recorder.ProxyAddrs = map[string]bool{opts.ProxyListen.String(): true}
		fmt.Printf("proxy: ext_proc on %s; Envoy bootstrap %s (proxy %s)\n", opts.ExtProcSocket, opts.EnvoyConfig, opts.ProxyListen)
		if t.Mode != TransparentOff {
			fmt.Printf("transparent: %s; listener 127.0.0.1:%d and [::1]:%d; exceptions %v; UDP allowed to %v\n",
				t.Mode, t.Port, t.Port, t.Exceptions, t.UDPExceptions)
		}
		if relay != nil {
			relay.xp = xp
			fmt.Printf("quic: relay on 127.0.0.1:%d and [::1]:%d; UDP 443 from runs is decided by server name\n", t.QUICPort, t.QUICPort)
		}
	}

	if gateway {
		xp = NewExtProcServer(api, "", httpEvents)
		xp.Gateway = &SubstrateGateway{TrustDomain: opts.ActorTrustDomain}
		xp.Directory = directory
		if err := xp.ListenGateway(opts.Gateway); err != nil {
			api.Close()
			closeAudit()
			return nil, err
		}
		peers := opts.Gateway.Peers
		if len(peers) == 0 {
			peers = []string{SubstratePeer}
		}
		fmt.Printf("substrate: ext_proc for Substrate's egress gateway on %s (TLS; clients %v)\n", opts.Gateway.Addr, peers)
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
		resolver:   resolver,
		identity:   opts.Identity,
		ca:         proxyCA,
		terminated: proxyTerminated,
		cmgr:       cmgr,
		audit:      audit,
		recorder:   recorder,
		api:        api,
		extproc:    xp,
		httpEvents: httpEvents,
		policyDir:  opts.PolicyDir,
		deployment: t.DeploymentMode(),
		lsm:        lsm,
		quic:       quic,
		execHash:   t.ExecHash,
		uprobes:    t.TLSCapture,
		relay:      relay,
		tlsParser:  newTLSParser(),
		tlsStacks:  map[uint32]string{},
		stopChan:   make(chan bool),
		running:    false,
	}
	if xp != nil {
		o := opts
		na.proxyOpts = &o
	}
	api.Status = na.Status
	if r := audit.reader; r != nil && lsmFor(*t, credential) {
		// Every run may reach the run API (agentctl inside a run).
		if err := r.SetUnixNode([]string{opts.SocketPath}); err != nil {
			fmt.Fprintf(os.Stderr, "node agent: %v\n", err)
		}
	}
	// Per-run kernel policy: UDP and ICMP in transparent mode (milestone
	// 4.7), and with BPF LSM, Unix sockets and exec. The LSM writers do
	// nothing where it is not loaded.
	if r := audit.reader; r != nil && !credential && (t.Mode != TransparentOff || t.TLSCapture) {
		api.OnRestoreCapture = func(runCg uint64, path string) int { return r.TLSAttachRunning(path, runCg) }
		api.OnPolicy = func(runCg uint64, uid int, eff *policy.Effective, nested bool) error {
			var errs []error
			if err := r.SetTLSCapture(runCg, eff.CapturesTLS()); err != nil {
				errs = append(errs, fmt.Errorf("tls capture: %w", err))
			}
			if err := r.SetNetPolicy(runCg, eff.Net()); err != nil {
				errs = append(errs, fmt.Errorf("udp and icmp: %w", err))
			}
			pats, enforce := eff.UnixAllow(uid)
			if err := r.SetUnixPolicy(runCg, pats, enforce); err != nil {
				errs = append(errs, fmt.Errorf("unix policy: %w", err))
			}
			if err := r.SetExecPolicy(runCg, eff.ExecLayers()); err != nil {
				errs = append(errs, fmt.Errorf("exec policy: %w", err))
			}
			// Marked only once its policy is in place: the mark is what
			// makes the kernel stop using the parent's (milestone 4.6).
			if nested && len(errs) == 0 {
				if err := r.SetNestedRun(runCg); err != nil {
					errs = append(errs, fmt.Errorf("nested run: %w", err))
				}
			}
			err := errors.Join(errs...)
			if err != nil {
				fmt.Fprintf(os.Stderr, "node agent: run cgroup %d: %v\n", runCg, err)
			}
			return err
		}
		api.OnNestedEnd = func(runCg uint64) {
			r.ForgetNestedRun(runCg)
			r.SetTLSCapture(runCg, false)
		}
	}
	if xp != nil && resolver != nil {
		xp.Names = resolver.NamesFor
	}
	if r := audit.reader; r != nil && recorder != nil {
		recorder.LostFor = r.LostFor
	}
	// Limits (milestone 5.2): duration and egress bytes here, connection
	// and request rates in ext_proc, sharing the run's allowances.
	store, err := OpenCounterStore(d.Counters())
	if err != nil {
		fmt.Fprintf(os.Stderr, "node agent: counters: %v; counting afresh\n", err)
		store, _ = OpenCounterStore("")
	}
	buckets := NewRateBuckets()
	if xp != nil {
		xp.Rates = buckets
	}
	var bc byteCounter
	if r := audit.reader; r != nil && !credential {
		bc = r
	}
	na.limiter = NewLimiter(api, bc, store, buckets)
	if xp != nil {
		// Budgets (milestone 5.4) share the counter store.
		xp.Budgets = NewBudgetLedger(api, store)
		na.limiter.Ledger = xp.Budgets
	}
	api.OnRunStart, api.OnRunEnd = na.limiter.RunStarted, na.limiter.RunEnded
	if xp != nil || gw != nil {
		// Ask (milestone 5.5): requests held for a person's decision.
		asks := NewAskQueue()
		asks.OnChange = func(p PendingAsk) {
			if p.State == AskPending {
				fmt.Printf("ask: run %s holds request %s for a decision: %s (profile %s); agentctl approve %s, or deny it, within %s\n",
					p.RunID, p.ID, p.What, p.Layer, p.ID, p.Expires.Sub(p.Created).Round(time.Second))
			} else {
				fmt.Printf("ask: request %s of run %s: %s%s\n", p.ID, p.RunID, p.State, map[bool]string{true: " by " + p.By, false: ""}[p.By != ""])
			}
		}
		api.Asks = asks
		if xp != nil {
			xp.Asks = asks
		}
		if gw != nil {
			gw.Asks = asks
		}
		ended := api.OnRunEnd
		api.OnRunEnd = func(runID string, runCg uint64) {
			ended(runID, runCg)
			asks.ForgetRun(runID)
		}
	}
	// Give runs that outlived the previous node agent their grants back,
	// before anything serves and before the first heartbeat.
	rep, err := api.Restore()
	if err != nil {
		api.Close()
		closeAudit()
		return nil, fmt.Errorf("restoring runs: %w", err)
	}
	if rep.Restored+rep.Gone > 0 {
		fmt.Printf("restore: %s\n", rep)
	}
	na.restored = rep
	if r := audit.reader; r != nil {
		r.ReleaseHeldLSM()
	}
	na.limiter.Resume()

	return na, nil
}

// ReloadPolicy (re)loads the policy directory. On failure the policy in
// force stays, so a bad edit never leaves the node without policy; runs
// already bound keep their versions either way.
func (na *NodeAgent) ReloadPolicy() error {
	set, err := loadNodePolicy(na.policyDir, na.cmgr != nil, na.identity == "actor", na.deployment, na.lsm, na.quic, na.execHash, na.uprobes)
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
	ec := EnvoyConfig{ProxyListen: opts.ProxyListen, ExtProcSocket: opts.ExtProcSocket,
		AdminSocket: opts.EnvoyAdmin, Terminate: hosts, UpstreamCA: opts.EnvoyUpstreamCA}
	if opts.Identity == "actor" {
		// Copied where Envoy reads its other certificates, in the
		// directory it shares with the node agent.
		at := &ActorListenerTLS{CertPath: filepath.Join(tlsDir, "proxy.crt"), KeyPath: filepath.Join(tlsDir, "proxy.key"),
			ClientCA: filepath.Join(tlsDir, "actor-ca.pem")}
		for src, dst := range map[string]string{opts.ActorProxyCert: at.CertPath, opts.ActorProxyKey: at.KeyPath, opts.ActorCA: at.ClientCA} {
			data, err := os.ReadFile(src)
			if err != nil {
				return nil, err
			}
			if err := writeFileAtomicOwned(dst, data, 0o600, envoyUID); err != nil {
				return nil, err
			}
		}
		ec.ActorTLS = at
	}
	if opts.Transparent.Mode != "" && opts.Transparent.Mode != TransparentOff {
		ec.TransparentPort = opts.Transparent.Port
	}
	boot, err := EnvoyBootstrap(ec)
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
// lsmFor says whether the BPF LSM socket hooks will be governing runs.
func lsmFor(t TransparentOptions, credential bool) bool {
	return !credential && t.Mode != TransparentOff && BPFLSMActive()
}

func loadNodePolicy(dir string, kernelIdentity, actors bool, mode policy.DeploymentMode, lsm, quic, execHash, uprobes bool) (*policy.Set, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		fmt.Printf("policy: %s does not exist; runs are unprofiled\n", dir)
		return nil, nil
	}
	set, err := LoadPolicyDir(dir, policy.Options{Mode: mode, Linux: kernelIdentity, KernelLSM: lsm, QUIC: quic, ExecHash: execHash,
		Uprobes: uprobes, Actors: actors}, os.Geteuid() == 0)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, p := range set.Compiled.Profiles {
		names = append(names, p.Name+"@"+p.Profile.ShortVersion())
	}
	fmt.Printf("policy: loaded %s: %s\n", dir, strings.Join(names, ", "))
	if set.Prices != nil {
		fmt.Printf("policy: model prices for %d patterns (%s)\n", len(set.Prices.Spec.Models), set.Prices.Metadata.Name)
	}
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
	if na.resolver != nil {
		na.resolver.Close()
	}
	if na.relay != nil {
		na.relay.Close()
	}
	if na.api != nil {
		na.api.Close()
	}
	if na.limitDone != nil {
		close(na.limitDone)
		na.limitDone = nil
		if err := na.limiter.store.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "node agent: saving counters: %v\n", err)
		}
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
	if na.resolver != nil {
		go na.resolver.Serve()
	}
	if na.relay != nil {
		go na.relay.Serve()
	}
	if na.limiter != nil {
		na.limitDone = make(chan struct{})
		go na.limiter.Run(time.Second, na.limitDone)
	}
	if na.proxyOpts != nil && na.audit.reader != nil {
		na.audit.reader.SetHealth(na.health)
		go na.watchEnvoy()
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
	case EventTLSData, EventTLSExit:
		// TLS plaintext (milestone 6.2): parsed here, never recorded.
		var reqs []TLSRequest
		lib := ""
		if d, ok := event.Data.(TLSData); ok {
			lib = d.Lib
			if v := na.tlsStacks[event.PID]; (lib == "go" || lib == "bundled") && v != "" {
				lib = v
			}
			reqs = na.tlsParser.feed(event.PID, d.Obj, d.Write, d.Data, d.Len)
		} else {
			lib = na.tlsStacks[event.PID]
			delete(na.tlsStacks, event.PID)
			reqs = na.tlsParser.close(event.PID)
		}
		for _, r := range reqs {
			ev := event
			ev.Type, ev.Data = EventTLS, TLSEventData{TLSRequest: r, Lib: lib}
			if lib == "" {
				ev.Data = TLSEventData{TLSRequest: r, Lib: "libssl"}
			}
			na.processEvent(ev)
		}
		return
	case EventTLSProgram:
		d, ok := event.Data.(TLSProgramData)
		if !ok {
			return
		}
		if d.Probed {
			na.tlsStacks[event.PID] = d.Lib
			fmt.Printf("%s [TLS] run=%d pid=%d %s: %s probed\n", ts, event.RunCgroupID, event.PID, d.Path, d.Stack)
		} else {
			delete(na.tlsStacks, event.PID)
			fmt.Printf("%s [TLS] run=%d pid=%d %s: %s not visible: %s\n", ts, event.RunCgroupID, event.PID, d.Path, d.Stack, d.Reason)
		}
	case EventTLS:
		d := event.Data.(TLSEventData)
		extra := ""
		if d.Tool != "" {
			extra = " mcp=" + d.MCPMethod + ":" + d.Tool
		}
		fmt.Printf("%s [TLS] run=%d pid=%d %s %s %s%s status=%d (%s)%s\n", ts, event.RunCgroupID, event.PID, d.Proto, d.Method, d.Host, d.Path, d.Status, d.Lib, extra)
	case EventExec:
		d := event.Data.(ExecData)
		fmt.Printf("%s [EXEC] run=%d cgroup=%d pid=%d ppid=%d binary=%s args=%q\n",
			ts, event.RunCgroupID, event.CgroupID, event.PID, d.PPID, d.BinaryPath, d.Args)
	case EventConnect:
		d := event.Data.(ConnectData)
		v := ""
		if d.Verdict != "" {
			v = " verdict=" + strconv.Quote(d.Verdict)
		}
		fmt.Printf("%s [CONNECT] run=%d cgroup=%d pid=%d proto=%s dst=%s%s\n",
			ts, event.RunCgroupID, event.CgroupID, event.PID, d.Protocol,
			net.JoinHostPort(d.DstIP, strconv.Itoa(int(d.DstPort))), v)
	case EventDNS:
		d := event.Data.(DNSData)
		extra := ""
		if d.Decision != "" {
			extra = " decision=" + d.Decision
			if d.Enforced {
				extra += " (NXDOMAIN)"
			}
			if len(d.WouldDeny) > 0 {
				extra += " would-deny=" + strings.Join(d.WouldDeny, ",")
			}
			if d.ECHStripped > 0 {
				extra += fmt.Sprintf(" ech-stripped=%d", d.ECHStripped)
			}
		}
		fmt.Printf("%s [DNS] run=%d cgroup=%d server=%s query=%s %s rcode=%s addrs=%v%s\n",
			ts, event.RunCgroupID, event.CgroupID, d.Server, d.Query, d.QType, d.RCode, d.Addrs(), extra)
	case EventExecPath:
		d := event.Data.(ExecPathData)
		extra := ""
		if d.Hash != "" {
			extra = " " + d.Hash
			if d.HashCached {
				extra += " (cached)"
			}
		}
		if d.HashMismatch {
			extra += " hash-mismatch"
		}
		if d.HashError {
			extra += " hash-error"
		}
		fmt.Printf("%s [EXEC PATH] run=%d pid=%d %s trusted=%v verdict=%q%s\n", ts, event.RunCgroupID, event.PID, d.Path, d.Trusted, d.Verdict, extra)
	case EventUnix:
		d := event.Data.(UnixData)
		kind := "stream"
		if d.Datagram {
			kind = "dgram"
		}
		fmt.Printf("%s [UNIX] run=%d pid=%d %s %s peer-cgroup=%d verdict=%q\n", ts, event.RunCgroupID, event.PID, kind, d.Path, d.PeerCgroup, d.Verdict)
	case EventSocket:
		d := event.Data.(SocketData)
		fmt.Printf("%s [SOCKET] run=%d pid=%d %s %s type=%d proto=%d socket-cgroup=%d verdict=%q\n", ts, event.RunCgroupID,
			event.PID, d.Op, d.Family, d.Type, d.Protocol, d.SocketCgroup, d.Verdict)
	case EventDrop:
		d := event.Data.(DropData)
		fmt.Printf("%s [DROP] run=%d proto=%s dst=%s count=%d\n", ts, event.RunCgroupID, d.Protocol,
			net.JoinHostPort(d.DstIP, strconv.Itoa(int(d.DstPort))), d.Count)
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
	case EventContent:
		d := event.Data.(ContentData)
		var hits []string
		for _, h := range d.Hits {
			hits = append(hits, fmt.Sprintf("%s/%s:%s×%d", h.Layer, h.Rule, h.Action, h.Count))
		}
		extra := ""
		if d.Reason != "" {
			extra = " reason=" + strconv.Quote(d.Reason)
		}
		fmt.Printf("%s [CONTENT] run=%d %s %s%s %s decision=%s hits=[%s]%s\n", ts, event.RunCgroupID, d.Method,
			net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port))), d.Path, d.Where, d.Decision, strings.Join(hits, " "), extra)
	case EventUsage:
		d := event.Data.(UsageData)
		extra := ""
		if d.Estimated {
			extra += " estimated"
		}
		if d.Refused != "" {
			extra += " refused=" + strconv.Quote(d.Refused)
		}
		for _, b := range d.Budgets {
			extra += fmt.Sprintf(" budget=%s/%s:%dtok,$%.4f", b.Layer, b.Rule, b.Tokens, b.CostUSD)
		}
		fmt.Printf("%s [USAGE] run=%d %s %s%s model=%q status=%d in=%d out=%d cache=%d cost=$%.6f%s\n", ts, event.RunCgroupID, d.Method,
			net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port))), d.Path, d.Model, d.Status, d.Usage.Input, d.Usage.Output,
			d.Usage.CacheRead+d.Usage.CacheWrite, d.CostUSD, extra)
	case EventModel:
		d := event.Data.(ModelData)
		extra := ""
		if len(d.WouldDeny) > 0 {
			extra += " would-deny=" + strings.Join(d.WouldDeny, ",")
		}
		if d.Reason != "" {
			extra += " reason=" + strconv.Quote(d.Reason)
		}
		fmt.Printf("%s [MODEL] run=%d %s %s%s %s model=%q decision=%s rule=%s/%s%s\n", ts, event.RunCgroupID, d.Method,
			net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port))), d.Path, d.Where, d.Model, d.Decision, d.Layer, d.Rule, extra)
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
		if d.Transparent {
			extra += " transparent orig=" + d.OrigDst
			if d.SNI != "" {
				extra += " sni=" + d.SNI
			}
			if d.AddrMismatch {
				extra += " addr-mismatch"
			}
			if d.ResolvedName != "" {
				extra += " by-name=" + d.ResolvedName
			}
		}
		fmt.Printf("%s [HTTP] run=%d %s decision=%s%s\n", ts, event.RunCgroupID, what, d.Decision, extra)
	case EventRunStart:
		fmt.Printf("%s [RUN START] run=%d path=%s\n", ts, event.RunCgroupID, event.Data.(RunData).CgroupPath)
	case EventRunEnd:
		if na.resolver != nil {
			na.resolver.Forget(event.RunCgroupID)
		}
		if na.audit != nil && na.audit.reader != nil {
			na.audit.reader.ForgetUnixPolicy(event.RunCgroupID)
			na.audit.reader.ForgetExecPolicy(event.RunCgroupID)
			na.audit.reader.ForgetNestedRun(event.RunCgroupID)
			na.audit.reader.ForgetNetPolicy(event.RunCgroupID)
			na.audit.reader.SetTLSCapture(event.RunCgroupID, false)
		}
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

// watchEnvoy probes Envoy every second (milestone 3.5). The heartbeat
// depends on the result in transparent mode, and the proxy's connect gate
// follows Envoy's cgroup across restarts.
func (na *NodeAgent) watchEnvoy() {
	transparent := na.proxyOpts.Transparent.Mode != "" && na.proxyOpts.Transparent.Mode != TransparentOff
	lastWhy := ""
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		st := probeEnvoy(na.proxyOpts.EnvoyAdmin, transparent)
		na.envoy.Store(st)
		why := ""
		switch {
		case !st.Ready:
			why = "Envoy is not ready"
		case !st.Dedicated:
			why = fmt.Sprintf("Envoy's cgroup %s holds other processes; run Envoy in its own (a container or a systemd unit)", st.Cgroup)
		}
		r := na.audit.reader
		if why == "" {
			if err := r.GateProxy(st.Cgroup); err != nil {
				why = err.Error()
			}
		}
		// Envoy gone: keep the gate where it was; a new Envoy is gated
		// once it is seen.
		na.gateWhy.Store(why)
		if why != lastWhy {
			if why == "" {
				fmt.Printf("proxy: Envoy (pid %d) gated: its connects to node-local addresses are refused in the kernel (cgroup %s)\n", st.PID, st.Cgroup)
			} else if st.Ready {
				fmt.Printf("proxy: Envoy's own connects are not gated: %s\n", why)
			}
			lastWhy = why
		}
		select {
		case <-tick.C:
		case <-na.stopChan:
			return
		}
	}
}

// health is the heartbeat's condition: Envoy ready, and serving the
// transparent listener.
func (na *NodeAgent) health() error {
	st, ok := na.envoy.Load().(EnvoyState)
	if !ok {
		return fmt.Errorf("Envoy not probed yet")
	}
	return st.Err
}

// Status reports the node's enforcement state.
func (na *NodeAgent) Status() NodeStatus {
	s := NodeStatus{Identity: na.identity, Transparent: TransparentOff}
	if na.proxyOpts != nil {
		s.Transparent = na.proxyOpts.Transparent.Mode
	}
	if st, ok := na.envoy.Load().(EnvoyState); ok {
		s.EnvoyReady, s.EnvoyPID, s.EnvoyCgroup = st.Ready, st.PID, st.Cgroup
		if st.Err != nil {
			s.HealthError = st.Err.Error()
		}
	}
	if r := na.audit.reader; r != nil {
		s.Healthy = r.Healthy() && s.HealthError == ""
		s.ProxyGated = r.GatedProxy() != ""
		s.ProxyRefused = r.ProxyRefused()
		s.LostEvents, s.SuppressedEvents = r.LostTotal()
		s.Sockets = r.LSMState()
	}
	if why, _ := na.gateWhy.Load().(string); !s.ProxyGated {
		s.ProxyGateWhy = why
		if why == "" {
			s.ProxyGateWhy = "no proxy, or cgroup identity is off"
		}
	}
	if na.resolver != nil {
		s.Resolver = strings.Join(na.resolver.upstreams, ", ")
	}
	if na.api != nil {
		s.ActiveRuns = na.api.ActiveRuns()
		if r := na.restored; r.Restored+r.Gone > 0 {
			s.Restored = r.String()
		}
		if na.audit != nil && na.audit.reader != nil {
			s.TLSCapture = na.audit.reader.TLSLibraries()
			if len(s.TLSCapture) > 0 {
				s.TLSGo = GoTLSVersions
			}
		}
	}
	return s
}
