// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	CgroupV2Root = "/sys/fs/cgroup"
	AgentsSubdir = "agents"
	RunPrefix    = "run-"
)

// CgroupManager manages cgroup v2 hierarchy for agent runs
type CgroupManager struct {
	root   string
	agents string
	runMap map[string]string
}

// NewCgroupManager creates a new cgroup manager
func NewCgroupManager() (*CgroupManager, error) {
	root := CgroupV2Root

	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return nil, fmt.Errorf("cgroup v2 not available at %s: %w", root, err)
	}

	agentsDir := filepath.Join(root, AgentsSubdir)
	if err := os.MkdirAll(agentsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create agents dir: %w", err)
	}

	cm := &CgroupManager{
		root:   root,
		agents: agentsDir,
		runMap: make(map[string]string),
	}

	return cm, nil
}

// RunIDFromPath extracts the run ID from a cgroup path
func RunIDFromPath(path string) string {
	dir := filepath.Base(path)
	if strings.HasPrefix(dir, RunPrefix) {
		return strings.TrimPrefix(dir, RunPrefix)
	}
	return ""
}

// GetCgroupID returns the kernel cgroup id for a cgroup v2 directory.
// cgroupfs exposes no id file; the id is the kernfs inode number of the
// directory, which is what bpf_get_current_cgroup_id() returns on 64-bit
// kernels.
func GetCgroupID(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, fmt.Errorf("failed to stat cgroup %s: %w", path, err)
	}
	return st.Ino, nil
}

// NewRunID returns a fresh random run identifier (12 hex chars).
func NewRunID() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("failed to generate run id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// CreateRunCgroup creates agents/run-<runID>. It fails if the cgroup
// already exists, so two runs can never share an identity.
func (cm *CgroupManager) CreateRunCgroup(runID string) (string, uint64, error) {
	cgroupPath := filepath.Join(cm.agents, RunPrefix+runID)

	if err := os.Mkdir(cgroupPath, 0755); err != nil {
		return "", 0, fmt.Errorf("failed to create cgroup: %w", err)
	}

	cgroupID, err := GetCgroupID(cgroupPath)
	if err != nil {
		unix.Rmdir(cgroupPath)
		return "", 0, fmt.Errorf("failed to get cgroup id: %w", err)
	}

	cm.runMap[runID] = cgroupPath

	return cgroupPath, cgroupID, nil
}

// DestroyRunCgroup ends a run: it kills anything still left in the run
// cgroup (daemonized children, stragglers), waits for the cgroup to empty,
// then removes it. cgroupfs only allows rmdir on an empty cgroup; its
// control files cannot be unlinked, so os.RemoveAll does not work here.
func (cm *CgroupManager) DestroyRunCgroup(runID string) error {
	cgroupPath, ok := cm.runMap[runID]
	if !ok {
		return fmt.Errorf("run cgroup not found for %s", runID)
	}

	populated, err := cgroupPopulated(cgroupPath)
	if err != nil {
		return err
	}
	if populated {
		// cgroup.kill (Linux 5.14+) SIGKILLs every process in the subtree.
		if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.kill"), []byte("1"), 0); err != nil {
			return fmt.Errorf("failed to kill remaining processes: %w", err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for populated {
			if time.Now().After(deadline) {
				return fmt.Errorf("cgroup %s still populated after kill", cgroupPath)
			}
			time.Sleep(10 * time.Millisecond)
			if populated, err = cgroupPopulated(cgroupPath); err != nil {
				return err
			}
		}
	}

	if err := removeCgroupTree(cgroupPath); err != nil {
		return err
	}

	delete(cm.runMap, runID)
	return nil
}

// cgroupPopulated reports whether any process lives in the cgroup subtree.
func cgroupPopulated(path string) (bool, error) {
	data, err := os.ReadFile(filepath.Join(path, "cgroup.events"))
	if err != nil {
		return false, fmt.Errorf("failed to read cgroup.events: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "populated" {
			return f[1] == "1", nil
		}
	}
	return false, fmt.Errorf("no populated field in %s/cgroup.events", path)
}

// removeCgroupTree rmdirs child cgroups depth-first, then path itself.
func removeCgroupTree(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("failed to list cgroup %s: %w", path, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			if err := removeCgroupTree(filepath.Join(path, e.Name())); err != nil {
				return err
			}
		}
	}
	if err := unix.Rmdir(path); err != nil {
		return fmt.Errorf("failed to remove cgroup %s: %w", path, err)
	}
	return nil
}

// GetRunCgroupPath returns the path for a run cgroup
func (cm *CgroupManager) GetRunCgroupPath(runID string) (string, bool) {
	path, ok := cm.runMap[runID]
	return path, ok
}

// ListActiveCgroups returns all active agent cgroups
func (cm *CgroupManager) ListActiveCgroups() []struct {
	RunID    string
	Path     string
	CgroupID uint64
} {
	var result []struct {
		RunID    string
		Path     string
		CgroupID uint64
	}

	entries, err := os.ReadDir(cm.agents)
	if err != nil {
		return result
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		runID := RunIDFromPath(filepath.Join(cm.agents, entry.Name()))
		if runID == "" {
			continue
		}
		path := filepath.Join(cm.agents, entry.Name())
		cgroupID, err := GetCgroupID(path)
		if err != nil {
			continue
		}
		result = append(result, struct {
			RunID    string
			Path     string
			CgroupID uint64
		}{runID, path, cgroupID})
	}

	return result
}

// GetAgentsDir returns the agents directory path
func (cm *CgroupManager) GetAgentsDir() string {
	return cm.agents
}
