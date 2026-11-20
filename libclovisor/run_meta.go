// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// DefaultRunSpoolDir is where agentctl leaves run metadata for the node
	// agent to pick up when the run ends.
	DefaultRunSpoolDir = "/run/clovisor/runs"
	// DefaultRunOutDir is where the node agent writes finished timelines.
	DefaultRunOutDir = "/var/lib/clovisor/runs"
)

// RunMeta is what agentctl knows about a run and the kernel does not: the
// full command line as given, who started it, and how it ended.
//
// This file handoff is an interim channel; the node-agent cgroup API
// (design §5.4) replaces it.
type RunMeta struct {
	RunID     string     `json:"run_id"`
	Command   []string   `json:"command"`
	Cwd       string     `json:"cwd,omitempty"`
	UID       int        `json:"uid"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	ExitCode  *int       `json:"exit_code,omitempty"`
}

func runMetaPath(dir, runID string) string {
	return filepath.Join(dir, runID+".json")
}

// WriteRunMeta atomically writes m into dir, creating dir if needed.
func WriteRunMeta(dir string, m RunMeta) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create %s: %w", dir, err)
	}
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return writeFileAtomic(runMetaPath(dir, m.RunID), data, 0600)
}

// ReadRunMeta reads the metadata for runID from dir.
func ReadRunMeta(dir, runID string) (RunMeta, error) {
	var m RunMeta
	data, err := os.ReadFile(runMetaPath(dir, runID))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("bad run metadata %s: %w", runMetaPath(dir, runID), err)
	}
	return m, nil
}

// RemoveRunMeta deletes the metadata for runID, if any.
func RemoveRunMeta(dir, runID string) error {
	err := os.Remove(runMetaPath(dir, runID))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// writeFileAtomic writes data to a temp file next to path and renames it
// into place, so readers never see a partial file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
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
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
