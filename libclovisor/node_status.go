// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

// EnvoyState is what the node agent last learned from Envoy's admin
// socket (milestone 3.5).
type EnvoyState struct {
	Ready       bool
	Transparent bool // serves the transparent listener
	PID         int
	Cgroup      string // relative to the cgroup root
	Dedicated   bool   // the cgroup holds only Envoy
	Err         error
}

// NodeStatus is the node's enforcement state, for agentctl status.
type NodeStatus struct {
	Identity    string `json:"identity"`
	Transparent string `json:"transparent"`
	// Healthy: the heartbeat is being written, so runs are served. False
	// in enforce mode means connects from runs are refused.
	Healthy     bool   `json:"healthy"`
	HealthError string `json:"health_error,omitempty"`
	EnvoyReady  bool   `json:"envoy_ready"`
	EnvoyPID    int    `json:"envoy_pid,omitempty"`
	EnvoyCgroup string `json:"envoy_cgroup,omitempty"`
	// ProxyGated: the proxy's own connects to node-local addresses are
	// refused in the kernel. ProxyRefused counts those refusals.
	ProxyGated   bool   `json:"proxy_gated"`
	ProxyGateWhy string `json:"proxy_gate_why,omitempty"`
	ProxyRefused uint64 `json:"proxy_refused"`
	LostEvents   uint64 `json:"lost_events"`
	// SuppressedEvents exceeded a run's event budget and were not reported.
	SuppressedEvents uint64 `json:"suppressed_events"`
	Resolver         string `json:"resolver,omitempty"`
	// Sockets is what the BPF LSM socket hooks do (milestones 4.1, 4.3).
	Sockets    string `json:"sockets,omitempty"`
	ActiveRuns int    `json:"active_runs"`
}
