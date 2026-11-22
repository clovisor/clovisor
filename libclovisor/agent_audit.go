// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

// AgentAudit provides the core functionality for agent audit tracking
package clovisor

import (
	"fmt"
	"time"
)

// Event types
const (
	EventExec = iota
	EventConnect
	EventRunStart // a run cgroup (agents/<name>) was created
	EventRunEnd   // a run cgroup was removed; always the run's last event
	EventDNS      // a resolver reply delivered to a socket in a run
	EventHTTP     // a request through the node's proxy, and its decision
	EventMCP      // an MCP operation through the local gateway, and its decision
)

// AuditEvent represents an audit event
type AuditEvent struct {
	Type      int
	Timestamp time.Time
	CgroupID  uint64 // leaf cgroup of the task (run or tool-call child)
	// RunCgroupID is the agents/run-<id> ancestor; equals CgroupID when
	// the task sits directly in the run cgroup.
	RunCgroupID uint64
	PID         uint32
	PPID        uint32
	Data        interface{}
}

// ExecData contains execution event data
type ExecData struct {
	BinaryPath string
	PID        uint32
	PPID       uint32
	Args       []string
}

// RunData describes a run cgroup appearing or disappearing.
type RunData struct {
	// Path relative to the cgroup v2 root, e.g. /agents/run-1a2b3c.
	CgroupPath string
}

// ConnectData contains connection event data
type ConnectData struct {
	SrcIP    string
	SrcPort  uint16
	DstIP    string
	DstPort  uint16
	Protocol string
	// Verdict is what transparent mode did with the connect (milestone
	// 3.1); empty when it is off.
	Verdict string
}

// AgentAudit manages audit event collection
type AgentAudit struct {
	reader      *EBPFReader
	eventCh     chan AuditEvent
	stopCh      chan bool
	forwardDone chan bool
	running     bool
}

// NewAgentAudit creates a new agent audit instance
func NewAgentAudit() (*AgentAudit, error) {
	audit := &AgentAudit{
		eventCh: make(chan AuditEvent, 1000),
		stopCh:  make(chan bool),
	}

	return audit, nil
}

// NewAgentAuditWithBPF creates a new agent audit instance with BPF reader
// that reports tasks under the given agents cgroup.
func NewAgentAuditWithBPF(bpfObjPath, agentsDir string, agentsCgroupID uint64, agentsLevel uint32, t TransparentOptions) (*AgentAudit, error) {
	reader, err := NewEBPFReader(bpfObjPath, agentsDir, agentsCgroupID, agentsLevel, t)
	if err != nil {
		return nil, fmt.Errorf("failed to create BPF reader: %w", err)
	}

	audit := &AgentAudit{
		reader:  reader,
		eventCh: make(chan AuditEvent, 1000),
		stopCh:  make(chan bool),
	}

	return audit, nil
}

// Start begins event collection
func (a *AgentAudit) Start() error {
	if a.running {
		return fmt.Errorf("agent audit already running")
	}

	// Initialize stop channel if nil
	if a.stopCh == nil {
		a.stopCh = make(chan bool)
	}

	// Initialize forwardDone channel if nil
	if a.forwardDone == nil {
		a.forwardDone = make(chan bool)
	}

	// Start BPF reader if available
	if a.reader != nil {
		if err := a.reader.Start(); err != nil {
			return fmt.Errorf("failed to start BPF reader: %w", err)
		}

		// Start event forwarding from BPF reader
		go a.forwardEvents()
	}

	a.running = true
	return nil
}

// Stop stops event collection
func (a *AgentAudit) Stop() error {
	if !a.running {
		return fmt.Errorf("agent audit not running")
	}

	// Signal stop to forwardEvents
	close(a.stopCh)

	// Stop BPF reader if available
	if a.reader != nil {
		if err := a.reader.Stop(); err != nil {
			return fmt.Errorf("failed to stop BPF reader: %w", err)
		}

		// Wait for forward goroutine to finish
		if a.forwardDone != nil {
			<-a.forwardDone
		}
	}

	// Close the event channel to signal handleEvents to stop
	close(a.eventCh)

	a.running = false
	return nil
}

// Events returns the event channel
func (a *AgentAudit) Events() <-chan AuditEvent {
	return a.eventCh
}

// forwardEvents forwards events from BPF reader to audit event channel
func (a *AgentAudit) forwardEvents() {
	defer func() {
		if a.forwardDone != nil {
			close(a.forwardDone)
		}
	}()

	for {
		select {
		case event, ok := <-a.reader.Events():
			if !ok {
				return
			}
			select {
			case a.eventCh <- event:
			case <-a.stopCh:
				return
			}
		case <-a.stopCh:
			return
		}
	}
}
