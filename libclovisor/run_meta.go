// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultRunOutDir is where the node agent writes finished timelines.
const DefaultRunOutDir = "/var/lib/clovisor/runs"

// RunMeta is what the client of the run API knows about a run and the
// kernel does not: the command line as given, who started it, and how it
// ended.
type RunMeta struct {
	RunID     string     `json:"run_id"`
	Command   []string   `json:"command"`
	Cwd       string     `json:"cwd,omitempty"`
	UID       int        `json:"uid"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	ExitCode  *int       `json:"exit_code,omitempty"`
	Policy    *RunPolicy `json:"policy,omitempty"`
	// Calls are the run's tool calls with cgroups of their own (milestone
	// 4.5), and its MCP servers.
	Calls []CallMeta `json:"calls,omitempty"`
	// Parent is the run this one was started from inside, for a nested
	// run (milestone 4.6); Children are the runs started from inside it.
	Parent   string   `json:"parent,omitempty"`
	Children []string `json:"children,omitempty"`
	// EndReason says why the node agent ended the run, when it did
	// (milestone 5.2: a duration limit, or its parent's).
	EndReason string `json:"end_reason,omitempty"`
	// EgressBytes is what the run sent, nested runs included, as the
	// kernel counted it (milestone 5.2).
	EgressBytes *uint64 `json:"egress_bytes,omitempty"`
	// Limits are the limits the run reached, and what was done.
	Limits []LimitHit `json:"limits,omitempty"`
	// Budgets are what the run spent of the budgets it owns, nested runs
	// included (milestone 5.4).
	Budgets []BudgetState `json:"budgets,omitempty"`
}

// LimitHit is one limit a run reached (milestone 5.2).
type LimitHit struct {
	At     time.Time `json:"at"`
	Limit  string    `json:"limit"` // duration, egress_bytes
	Layer  string    `json:"layer"`
	Value  string    `json:"value"`  // the limit, e.g. 30m, 100Mi
	Action string    `json:"action"` // ended, revoked, would end, would revoke
	// Run is the run that holds the layer, when it is not this one: an
	// ancestor whose limit this run's traffic counted toward.
	Run string `json:"run,omitempty"`
}

// CallMeta is one tool call in a cgroup of its own below its run
// (run-<id>/call-<n>), or an MCP server (run-<id>/mcp-<name>). Name is what
// the harness called it: a label, not identity.
type CallMeta struct {
	ID        string     `json:"id"`
	Name      string     `json:"name,omitempty"`
	Command   []string   `json:"command,omitempty"`
	CgroupID  uint64     `json:"cgroup_id"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	ExitCode  *int       `json:"exit_code,omitempty"`
}

// RunPolicy records which policy governed a run, by version (design
// §5.6): the granted profile, then any clamps, in the order applied.
type RunPolicy struct {
	// Parent is the run a nested run's policy is bounded by (milestone
	// 4.6); its layers come first, their sources naming the run.
	Parent    string        `json:"parent,omitempty"`
	Requested string        `json:"requested,omitempty"`
	Ceiling   string        `json:"ceiling"`
	Reason    string        `json:"reason"`
	Layers    []PolicyLayer `json:"layers"`
}

// Granted is the layer the run was granted itself: the first, or for a
// nested run, the first not inherited from its parent. nil if there is
// none (a nested run bound by its parent's layers only).
func (rp *RunPolicy) Granted() *PolicyLayer {
	for i := range rp.Layers {
		if rp.Parent == "" || !strings.HasPrefix(rp.Layers[i].Source, "run ") {
			return &rp.Layers[i]
		}
	}
	return nil
}

// PolicyLayer is one profile in a run's effective policy.
type PolicyLayer struct {
	Profile string    `json:"profile"`
	Version string    `json:"version"` // sha256:<12 hex>
	Mode    string    `json:"mode"`
	Source  string    `json:"source"` // granted, ceiling clamp, clamped by ..., revoked by ...
	At      time.Time `json:"at"`
}

// writeFileAtomic writes data to a temp file next to path and renames it
// into place, so readers never see a partial file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	return writeFileAtomicOwned(path, data, perm, -1)
}

// writeFileAtomicOwned is writeFileAtomic, also chowning the file to uid
// (unless uid is negative).
func writeFileAtomicOwned(path string, data []byte, perm os.FileMode, uid int) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if uid >= 0 {
		if err := f.Chown(uid, -1); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
