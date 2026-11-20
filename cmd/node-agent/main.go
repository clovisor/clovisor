// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	clovisor "github.com/clovisor/clovisor/libclovisor"
	log "github.com/sirupsen/logrus"
)

var (
	bpfObj   = flag.String("bpf", "libclovisor/ebpf/agent_audit.o", "Path to the compiled audit BPF object")
	outDir   = flag.String("out", clovisor.DefaultRunOutDir, "Directory for per-run timeline files")
	spoolDir = flag.String("spool", clovisor.DefaultRunSpoolDir, "Directory where agentctl leaves run metadata")
)

func main() {
	flag.Parse()
	log.Info("Clovisor Node Agent starting...")

	// Create and initialize the node agent with BPF audit attached
	agent, err := clovisor.NewNodeAgentWithBPF(clovisor.NodeAgentOptions{
		BPFObjPath: *bpfObj,
		OutDir:     *outDir,
		SpoolDir:   *spoolDir,
	})
	if err != nil {
		log.Fatalf("Failed to create node agent: %v", err)
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Run the agent in a goroutine so we can wait for signals
	done := make(chan error)
	go func() {
		done <- agent.Run()
	}()

	// Wait for shutdown signal or done channel
	select {
	case err := <-done:
		log.Infof("Agent finished: %v", err)
		return
	case <-sigChan:
		log.Info("Shutdown signal received, stopping node agent...")
	}

	agent.Stop()
}
