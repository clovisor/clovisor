// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// Transparent modes (milestone 3.1, design §6.5 rule 1).
const (
	// TransparentOff leaves connects alone: only traffic a run sends to
	// the explicit proxy is governed.
	TransparentOff = "off"
	// TransparentAudit records what enforce would do, and does nothing.
	TransparentAudit = "audit"
	// TransparentEnforce redirects every TCP connect from a run to the
	// transparent listener, or refuses it while the node agent is down.
	TransparentEnforce = "enforce"
)

const (
	// DefaultTransparentPort is the transparent listener's port, on
	// 127.0.0.1 and ::1.
	DefaultTransparentPort = 15001
	// DefaultResolverPort is the local resolver's port, on 127.0.0.1 and
	// ::1, UDP and TCP (milestone 3.4).
	DefaultResolverPort = 15053
	// DefaultBPFPinDir holds the links that must outlive the node agent.
	DefaultBPFPinDir = "/sys/fs/bpf/clovisor"
	// DefaultHeartbeatStale is how old the node agent's heartbeat may be
	// before connects are refused.
	DefaultHeartbeatStale = 3 * time.Second
	// maxTransparentExceptions matches MAX_EXCEPTIONS in agent_audit.c.
	maxTransparentExceptions = 4
)

// TransparentOptions configure the connect hooks.
type TransparentOptions struct {
	Mode string // off, audit or enforce; empty is off
	// Port of the transparent listener; DefaultTransparentPort if 0.
	Port uint16
	// DNSPort is the local resolver's port; DefaultResolverPort if 0. In
	// audit and enforce, every DNS query from a run goes there.
	DNSPort uint16
	// Exceptions are reached directly: the explicit proxy and the MCP
	// gateway. An unspecified address matches any loopback address.
	Exceptions []netip.AddrPort
	// UDPExceptions are the UDP destinations runs may reach (milestone
	// 3.3); all other UDP but DNS is refused. Same address rule.
	UDPExceptions []netip.AddrPort
	// Stale is the heartbeat age that counts as down;
	// DefaultHeartbeatStale if 0.
	Stale time.Duration
	// PinDir is where enforce mode pins its links; DefaultBPFPinDir if empty.
	PinDir string
}

func (t *TransparentOptions) normalize() error {
	switch t.Mode {
	case "":
		t.Mode = TransparentOff
	case TransparentOff, TransparentAudit, TransparentEnforce:
	default:
		return fmt.Errorf("transparent mode must be off, audit or enforce, not %q", t.Mode)
	}
	if t.Port == 0 {
		t.Port = DefaultTransparentPort
	}
	if t.DNSPort == 0 {
		t.DNSPort = DefaultResolverPort
	}
	if t.DNSPort == t.Port {
		return fmt.Errorf("the resolver and the transparent listener need different ports")
	}
	if t.Stale == 0 {
		t.Stale = DefaultHeartbeatStale
	}
	if t.PinDir == "" {
		t.PinDir = DefaultBPFPinDir
	}
	if len(t.Exceptions) > maxTransparentExceptions {
		return fmt.Errorf("at most %d transparent exceptions", maxTransparentExceptions)
	}
	if len(t.UDPExceptions) > maxTransparentExceptions {
		return fmt.Errorf("at most %d UDP exceptions", maxTransparentExceptions)
	}
	return nil
}

// DeploymentMode is the policy deployment mode a transparent mode gives:
// what the receipt reports.
func (t TransparentOptions) DeploymentMode() policy.DeploymentMode {
	switch t.Mode {
	case TransparentEnforce:
		return policy.Transparent
	case TransparentAudit:
		return policy.TransparentAudit
	}
	return policy.ExplicitProxy
}

// Connect verdicts, as the kernel reports them (V_* in agent_audit.c).
var connectVerdicts = map[uint32]string{
	0:  "",
	1:  "redirect",
	2:  "refused: node agent down",
	3:  "same-run loopback",
	4:  "exception",
	5:  "loopback, nothing listening",
	6:  "would redirect",
	7:  "would refuse: node agent down",
	8:  "dns: local resolver",
	9:  "refused: UDP",
	10: "would refuse: UDP",
}

// Connect verdicts a timeline treats specially.
const (
	VerdictRedirect = "redirect"
	VerdictRefused  = "refused: node agent down"
	VerdictUDP      = "refused: UDP"
)
