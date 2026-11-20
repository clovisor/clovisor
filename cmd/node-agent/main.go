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
	bpfObj   = flag.String("bpf", "libclovisor/ebpf/agent_audit.o", "Path to the compiled audit BPF object")
	outDir   = flag.String("out", clovisor.DefaultRunOutDir, "Directory for per-run timeline files")
	socket   = flag.String("socket", clovisor.DefaultRunAPISocket, "Unix socket for the run API used by agentctl")
	policies = flag.String("policy-dir", clovisor.DefaultPolicyDir, "Root-owned directory of profiles and ceilings; reloaded on SIGHUP")
	proxy    = flag.String("proxy-listen", "", "Enable the explicit proxy: Envoy listen address for runs, e.g. 127.0.0.1:18000")
	extSock  = flag.String("extproc-socket", clovisor.DefaultExtProcSocket, "Unix socket where ext_proc serves Envoy")
	envoyCfg = flag.String("envoy-config", "/run/clovisor/envoy.json", "Where to write the generated Envoy bootstrap")
	envoyUID = flag.String("envoy-uids", "101", "Comma-separated uids Envoy runs as, admitted to ext_proc (root always is)")
	nonRun   = flag.Bool("proxy-non-run", false, "Let processes outside any run use the proxy")
)

func proxyAddr() netip.AddrPort {
	if *proxy == "" {
		return netip.AddrPort{}
	}
	ap, err := netip.ParseAddrPort(*proxy)
	if err != nil {
		log.Fatalf("-proxy-listen: %v", err)
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
	agent, err := clovisor.NewNodeAgentWithBPF(clovisor.NodeAgentOptions{
		BPFObjPath:    *bpfObj,
		OutDir:        *outDir,
		SocketPath:    *socket,
		PolicyDir:     *policies,
		ProxyListen:   proxyAddr(),
		ExtProcSocket: *extSock,
		EnvoyConfig:   *envoyCfg,
		EnvoyUIDs:     uids(*envoyUID),
		NonRunProxy:   *nonRun,
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
