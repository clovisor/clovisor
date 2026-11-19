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
	"encoding/json"
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
	stopChan  chan bool
	running   bool
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
// audit BPF program, scoped to the agents cgroup subtree.
func NewNodeAgentWithBPF(bpfObjPath string) (*NodeAgent, error) {
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

	audit, err := NewAgentAuditWithBPF(bpfObjPath, cmgr.GetAgentsDir(), agentsID, level)
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

	// Close BPF reader if it exists
	if na.bpfReader != nil {
		na.bpfReader.Close()
		na.bpfReader = nil
	}

	// Stop the audit
	if err := na.audit.Stop(); err != nil {
		return fmt.Errorf("failed to stop audit: %w", err)
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
	go na.handleEvents()

	// Block forever - this is a daemon
	select {}
}

// handleEvents processes audit events
func (na *NodeAgent) handleEvents() {
	for event := range na.audit.Events() {
		na.processEvent(event)
	}
}

// Stop signals the node agent to stop
func (na *NodeAgent) StopSignal() {
	close(na.stopChan)
}

// processEvent processes a single audit event
func (na *NodeAgent) processEvent(event AuditEvent) {
	switch event.Type {
	case EventExec:
		execData := event.Data.(ExecData)
		fmt.Printf("%s [EXEC] run=%d cgroup=%d pid=%d binary=%s\n",
			event.Timestamp.Format(time.RFC3339Nano), event.RunCgroupID,
			event.CgroupID, event.PID, execData.BinaryPath)
	case EventConnect:
		connectData := event.Data.(ConnectData)
		fmt.Printf("%s [CONNECT] run=%d cgroup=%d pid=%d proto=%s dst=%s\n",
			event.Timestamp.Format(time.RFC3339Nano), event.RunCgroupID,
			event.CgroupID, event.PID, connectData.Protocol,
			net.JoinHostPort(connectData.DstIP, strconv.Itoa(int(connectData.DstPort))))
	}
}

// ExportEvents exports events to a JSON file
func (na *NodeAgent) ExportEvents(outputPath string) error {
	events := make([]map[string]interface{}, 0)

	// Read events from the channel (this would need to be buffered or we'd need
	// a way to collect events first)
	// For now, just create a placeholder
	event := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"type":      "placeholder",
	}
	events = append(events, event)

	data, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}
