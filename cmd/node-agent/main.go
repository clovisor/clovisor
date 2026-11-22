// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package main

import (
	"flag"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	clovisor "github.com/clovisor/clovisor/libclovisor"
	log "github.com/sirupsen/logrus"
)

var (
	identity = flag.String("identity", "", "How runs are known: cgroup (Linux, kernel audit) or credential (anywhere, a per-run proxy secret; a claim). Default: cgroup on Linux, credential elsewhere")
	rtDir    = flag.String("runtime-dir", "", "Directory for sockets and generated files (default /run/clovisor as root, a per-user directory otherwise)")
	stDir    = flag.String("state-dir", "", "Directory for timelines, the node CA and tool pins (default /var/lib/clovisor as root, a per-user directory otherwise)")
	bpfObj   = flag.String("bpf", "libclovisor/ebpf/agent_audit.o", "Path to the compiled audit BPF object (cgroup identity)")
	outDir   = flag.String("out", "", "Directory for per-run timeline files (default <state-dir>/runs)")
	socket   = flag.String("socket", "", "Unix socket for the run API used by agentctl (default <runtime-dir>/agent.sock)")
	policies = flag.String("policy-dir", clovisor.DefaultPolicyDir, "Directory of profiles and ceilings, root-owned when run as root; reloaded on SIGHUP")
	proxy    = flag.String("proxy-listen", "", "Enable the explicit proxy: Envoy listen address for runs, e.g. 127.0.0.1:18000")
	extSock  = flag.String("extproc-socket", "", "Unix socket where ext_proc serves Envoy (default <runtime-dir>/extproc.sock)")
	envoyCfg = flag.String("envoy-config", "", "Where to write the generated Envoy bootstrap (default <runtime-dir>/envoy.json)")
	envoyUID = flag.String("envoy-uids", defaultEnvoyUIDs(), "Comma-separated uids Envoy runs as, admitted to ext_proc (root and the node agent's uid always are)")
	nonRun   = flag.Bool("proxy-non-run", false, "Let processes outside any run use the proxy")
	mcpAddr  = flag.String("mcp-listen", "", "Enable the local MCP gateway on this loopback address, e.g. 127.0.0.1:18100")
	caDir    = flag.String("ca-dir", "", "Node CA for TLS termination, key readable only by the node agent (default <state-dir>/ca)")
	upCA     = flag.String("envoy-upstream-ca", "", "System trust store as Envoy sees it, to verify origins behind termination (default: the host's)")
	transp   = flag.String("transparent", "off", "Transparent mode (needs -proxy-listen and cgroup identity): off; audit (record what enforce would do); "+
		"enforce (every TCP connect from a run goes to Envoy's transparent listener or is refused, also while the node agent is down)")
	tPort  = flag.Uint("transparent-port", clovisor.DefaultTransparentPort, "Transparent listener port, on 127.0.0.1 and ::1")
	tStale = flag.Duration("transparent-stale", clovisor.DefaultHeartbeatStale, "How long after the node agent stops connects are refused")
)

// defaultEnvoyUIDs is the uid of the official Envoy image's user when the
// node agent is root; a user's node agent runs Envoy as that user.
func defaultEnvoyUIDs() string {
	if os.Geteuid() == 0 {
		return "101"
	}
	return ""
}

func dirs() clovisor.Dirs {
	d := clovisor.DefaultDirs()
	if *rtDir != "" {
		d.Runtime = *rtDir
	}
	if *stDir != "" {
		d.State = *stDir
	}
	return d
}

func proxyAddr() netip.AddrPort { return addrFlag("-proxy-listen", *proxy) }

func addrFlag(name, v string) netip.AddrPort {
	if v == "" {
		return netip.AddrPort{}
	}
	ap, err := netip.ParseAddrPort(v)
	if err != nil {
		log.Fatalf("%s: %v", name, err)
	}
	return ap
}

func uids(s string) []uint32 {
	var out []uint32
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		u, err := strconv.ParseUint(f, 10, 32)
		if err != nil {
			log.Fatalf("-envoy-uids: %v", err)
		}
		out = append(out, uint32(u))
	}
	return out
}

func main() {
	flag.Parse()
	log.Info("Clovisor Node Agent starting...")

	// Create and initialize the node agent with BPF audit attached
	agent, err := clovisor.NewNodeAgentFromOptions(clovisor.NodeAgentOptions{
		Identity:        *identity,
		Dirs:            dirs(),
		BPFObjPath:      *bpfObj,
		OutDir:          *outDir,
		SocketPath:      *socket,
		PolicyDir:       *policies,
		ProxyListen:     proxyAddr(),
		ExtProcSocket:   *extSock,
		EnvoyConfig:     *envoyCfg,
		EnvoyUIDs:       uids(*envoyUID),
		NonRunProxy:     *nonRun,
		MCPListen:       addrFlag("-mcp-listen", *mcpAddr),
		CADir:           *caDir,
		EnvoyUpstreamCA: *upCA,
		Transparent:     clovisor.TransparentOptions{Mode: *transp, Port: uint16(*tPort), Stale: *tStale},
	})
	// A policy that does not load is fatal at start: running without it
	// would silently leave runs unprofiled.
	if err != nil {
		log.Fatalf("Failed to create node agent: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Run the agent in a goroutine so we can wait for signals
	done := make(chan error)
	go func() {
		done <- agent.Run()
	}()

	for {
		select {
		case err := <-done:
			log.Infof("Agent finished: %v", err)
			return
		case sig := <-sigChan:
			if sig == syscall.SIGHUP {
				if err := agent.ReloadPolicy(); err != nil {
					log.Errorf("policy reload failed; keeping the policy in force: %v", err)
				}
				continue
			}
			log.Info("Shutdown signal received, stopping node agent...")
			agent.Stop()
			return
		}
	}
}
