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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// NodeAgent is the main daemon for node-level agent egress tracking
type NodeAgent struct {
	cmgr      *CgroupManager
	audit     *AgentAudit
	bpfReader *EBPFReader
	recorder  *RunRecorder
	api       *RunAPIServer
	stopChan  chan bool
	handled   chan struct{} // closed when handleEvents has drained
	running   bool
}

// NodeAgentOptions configures where run timelines go.
type NodeAgentOptions struct {
	BPFObjPath string
	OutDir     string // finished timelines; DefaultRunOutDir if empty
	SocketPath string // run API socket; DefaultRunAPISocket if empty
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

// NewNodeAgentWithBPF creates a node agent that loads and attaches the
// audit BPF program, scoped to the agents cgroup subtree, and writes one
// timeline per run.
func NewNodeAgentWithBPF(opts NodeAgentOptions) (*NodeAgent, error) {
	if opts.OutDir == "" {
		opts.OutDir = DefaultRunOutDir
	}
	if opts.SocketPath == "" {
		opts.SocketPath = DefaultRunAPISocket
	}

	cmgr, err := NewCgroupManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create cgroup manager: %w", err)
	}

	agentsID, err := GetCgroupID(cmgr.GetAgentsDir())
	if err != nil {
		return nil, fmt.Errorf("failed to read agents cgroup id: %w", err)
	}
	level, err := cgroupLevel(cmgr.GetAgentsDir())
	if err != nil {
		return nil, err
	}

	registry := NewRunRegistry()
	recorder, err := NewRunRecorder(cmgr.GetAgentsDir(), opts.OutDir, registry)
	if err != nil {
		return nil, err
	}

	audit, err := NewAgentAuditWithBPF(opts.BPFObjPath, cmgr.GetAgentsDir(), agentsID, level)
	if err != nil {
		return nil, fmt.Errorf("failed to create agent audit: %w", err)
	}

	// Listen only once BPF is attached, so no run can start unobserved.
	api, err := NewRunAPIServer(opts.SocketPath, cmgr, registry)
	if err != nil {
		audit.reader.Close()
		return nil, err
	}

	na := &NodeAgent{
		cmgr:     cmgr,
		audit:    audit,
		recorder: recorder,
		api:      api,
		stopChan: make(chan bool),
		running:  false,
	}

	return na, nil
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

	// Block forever - this is a daemon
	select {}
}

// handleEvents processes audit events
func (na *NodeAgent) handleEvents() {
	defer close(na.handled)
	for event := range na.audit.Events() {
		na.processEvent(event)
	}
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
