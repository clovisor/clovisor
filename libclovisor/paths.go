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
	"runtime"
)

// Dirs are where the node agent keeps its sockets and generated files
// (Runtime) and what must survive a restart (State).
type Dirs struct {
	Runtime string
	State   string
}

// SystemDirs are a root node agent's directories.
func SystemDirs() Dirs {
	if runtime.GOOS == "darwin" {
		return Dirs{Runtime: "/var/run/clovisor", State: "/Library/Application Support/Clovisor"}
	}
	return Dirs{Runtime: "/run/clovisor", State: "/var/lib/clovisor"}
}

// UserDirs are the directories of a node agent run as an ordinary user,
// as on a developer laptop. Such an agent cannot protect policy from the
// user, so it is advisory (design §4.3).
func UserDirs() (Dirs, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Dirs{}, err
	}
	if runtime.GOOS == "darwin" {
		base := filepath.Join(home, "Library", "Application Support", "Clovisor")
		return Dirs{Runtime: filepath.Join(base, "run"), State: base}, nil
	}
	state := filepath.Join(home, ".local", "state", "clovisor")
	if x := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(x) {
		state = filepath.Join(x, "clovisor")
	}
	rt := filepath.Join(state, "run")
	if x := os.Getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(x) {
		rt = filepath.Join(x, "clovisor")
	}
	return Dirs{Runtime: rt, State: state}, nil
}

// DefaultDirs are the directories for a node agent run with this euid.
func DefaultDirs() Dirs {
	if os.Geteuid() != 0 {
		if d, err := UserDirs(); err == nil {
			return d
		}
	}
	return SystemDirs()
}

// ClientDirs are where a client looks for the node agent: a user-level
// agent's, when one is running, else the system's.
func ClientDirs() Dirs {
	if d, err := UserDirs(); err == nil {
		if _, err := os.Stat(filepath.Join(d.Runtime, "agent.sock")); err == nil {
			return d
		}
	}
	return SystemDirs()
}

// Files within the directories.
func (d Dirs) APISocket() string     { return filepath.Join(d.Runtime, "agent.sock") }
func (d Dirs) ExtProcSocket() string { return filepath.Join(d.Runtime, "extproc.sock") }
func (d Dirs) EnvoyDir() string      { return filepath.Join(d.Runtime, "envoy") }
func (d Dirs) EnvoyConfig() string   { return filepath.Join(d.Runtime, "envoy.json") }
func (d Dirs) TrustBundle() string   { return filepath.Join(d.Runtime, "ca-bundle.pem") }
func (d Dirs) NodeCACert() string    { return filepath.Join(d.Runtime, "ca.crt") }
func (d Dirs) CADir() string         { return filepath.Join(d.State, "ca") }
func (d Dirs) Pins() string          { return filepath.Join(d.State, "mcp-pins.json") }
func (d Dirs) Runs() string          { return filepath.Join(d.State, "runs") }
func (d Dirs) Counters() string      { return filepath.Join(d.State, "counters.json") }

// Grants is where live runs' grants are kept across restarts (6.1).
func (d Dirs) Grants() string { return filepath.Join(d.State, "grants.json") }

// systemUpstreamCA is the trust store Envoy verifies origins against.
func systemUpstreamCA() string {
	for _, p := range systemBundles {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return systemBundles[0]
}
