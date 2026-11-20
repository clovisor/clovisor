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
}

// RunPolicy records which policy governed a run, by version (design
// §5.6): the granted profile, then any clamps, in the order applied.
type RunPolicy struct {
	Requested string        `json:"requested,omitempty"`
	Ceiling   string        `json:"ceiling"`
	Reason    string        `json:"reason"`
	Layers    []PolicyLayer `json:"layers"`
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
