// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// Grants (milestone 6.1): what each live run was granted, written at
// every change so a node agent that restarts gives runs still going the
// policy they had. Without it they came back unprofiled, their rules and
// revocations gone (6.0). The file is root's: a run's timeline also holds
// its layers, but belongs to the run's user, who could edit a clamp out.

// grantFile is the grants file.
type grantFile struct {
	Version int        `json:"version"`
	Runs    []runGrant `json:"runs"`
	// Profiles are the profile documents the runs' layers name, by
	// version, so a run keeps the version it was bound to (§5.6) even if
	// the policy directory changed while the node agent was down.
	Profiles map[string]*policy.AgentProfile `json:"profiles,omitempty"`
}

// runGrant is one live run.
type runGrant struct {
	RunID      string          `json:"run_id"`
	CgroupID   uint64          `json:"cgroup_id"`
	CgroupPath string          `json:"cgroup_path"` // relative to the agents directory
	UID        int             `json:"uid"`
	Creator    procIdentity    `json:"creator"` // the agentctl that created it, which may report its end
	Parent     string          `json:"parent,omitempty"`
	Started    time.Time       `json:"started"`
	Profiled   bool            `json:"profiled"`
	Layers     []grantLayer    `json:"layers,omitempty"`
	Ceiling    policy.NetGrant `json:"ceiling"`
	Meta       RunMeta         `json:"meta"`
}

// grantLayer is a layer by profile version, or a built-in one.
type grantLayer struct {
	Version string `json:"version,omitempty"`
	Builtin string `json:"builtin,omitempty"`
	Message string `json:"message,omitempty"`
	Source  string `json:"source"`
}

// procIdentity names a process across pid reuse: its pid and the start
// time the kernel gives it (field 22 of /proc/<pid>/stat).
type procIdentity struct {
	PID   int32  `json:"pid"`
	Start uint64 `json:"start"`
}

const grantFileVersion = 1

// saveGrants writes every live run's grants. Called after each change, so
// a node agent that dies at any point leaves the state of the last one.
// Errors are logged: a run must not fail because its record could not be
// written, but the operator should hear of it.
func (s *RunAPIServer) saveGrants() {
	if s.GrantsPath == "" || s.cm == nil {
		return
	}
	s.grantMu.Lock()
	defer s.grantMu.Unlock()
	f := grantFile{Version: grantFileVersion, Profiles: map[string]*policy.AgentProfile{}}
	s.mu.Lock()
	for runID := range s.active {
		g := runGrant{RunID: runID, CgroupID: s.runCg[runID], Parent: s.parentOf[runID], Creator: s.creators[runID]}
		if p, ok := s.cm.GetRunCgroupPath(runID); ok {
			if rel, err := filepath.Rel(s.cm.GetAgentsDir(), p); err == nil {
				g.CgroupPath = rel
			}
		}
		if b := s.bound[runID]; b != nil {
			g.Profiled, g.UID, g.Started, g.Ceiling = true, b.uid, b.started, b.eff.Ceiling
			for _, l := range b.eff.Layers {
				gl := grantLayer{Source: l.Source, Builtin: l.Profile.Builtin}
				if gl.Builtin != "" {
					gl.Message = l.Profile.DefaultMessage
				} else {
					gl.Version = l.Profile.Profile.Version()
					f.Profiles[gl.Version] = l.Profile.Profile
				}
				g.Layers = append(g.Layers, gl)
			}
		}
		f.Runs = append(f.Runs, g)
	}
	s.mu.Unlock()
	for i := range f.Runs {
		if m, ok := s.reg.Get(f.Runs[i].RunID); ok {
			f.Runs[i].Meta = m
			if !f.Runs[i].Profiled {
				f.Runs[i].UID, f.Runs[i].Started = m.UID, m.StartedAt
			}
		}
	}
	sort.Slice(f.Runs, func(i, j int) bool { return f.Runs[i].RunID < f.Runs[j].RunID })
	b, err := json.MarshalIndent(f, "", "  ")
	if err == nil {
		err = os.MkdirAll(filepath.Dir(s.GrantsPath), 0o755)
	}
	if err == nil {
		err = writeFileAtomic(s.GrantsPath, b, 0o600)
	}
	if err != nil {
		log.Printf("run api: saving grants: %v", err)
	}
}

// PendingGrants reads the grants file, for the node agent to know before
// it loads BPF whether runs await restoring. A missing file has none.
func PendingGrants(path string) (int, error) {
	f, err := readGrants(path)
	if err != nil {
		return 0, err
	}
	return len(f.Runs), nil
}

func readGrants(path string) (*grantFile, error) {
	var f grantFile
	if path == "" {
		return &f, nil
	}
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return &f, nil
	}
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%s must be a regular file no one else can write (mode %v)", path, st.Mode())
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 && sys.Uid != 0 {
		return nil, fmt.Errorf("%s must be owned by root", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if f.Version != grantFileVersion {
		return nil, fmt.Errorf("%s: version %d, want %d", path, f.Version, grantFileVersion)
	}
	return &f, nil
}

// RestoreReport says what Restore did.
type RestoreReport struct {
	Restored int      // runs given their grants back
	Revoked  []string // runs whose grants could not be rebuilt: "id: why"
	Gone     int      // runs that ended while the node agent was down
}

func (r RestoreReport) String() string {
	s := fmt.Sprintf("%d runs restored", r.Restored)
	if len(r.Revoked) > 0 {
		s += fmt.Sprintf(", %d revoked (%s)", len(r.Revoked), strings.Join(r.Revoked, "; "))
	}
	if r.Gone > 0 {
		s += fmt.Sprintf(", %d ended meanwhile", r.Gone)
	}
	return s
}

// Restore gives runs that outlived the previous node agent their grants
// back, before the run API serves and before the node reports healthy
// (milestone 6.1). Each run is bound as create binds a new one: the run
// API's maps, the registry, the limiter (OnRunStart) and the kernel
// (OnPolicy). A run whose layers cannot be rebuilt is revoked, never left
// unprofiled. Runs whose cgroups are gone are dropped. The restored runs
// belong to no connection until their agentctl reports their end
// (endFor), or the reaper ends them once they are empty.
func (s *RunAPIServer) Restore() (RestoreReport, error) {
	var rep RestoreReport
	if s.cm == nil {
		return rep, nil // credential identity: tokens do not survive, so runs fail closed at the proxy
	}
	f, err := readGrants(s.GrantsPath)
	if err != nil {
		return rep, err
	}
	var opts policy.Options
	if set := s.policy.Load(); set != nil {
		opts = set.Compiled.Options
	}
	compiled := map[string]*policy.CompiledProfile{}
	profile := func(version string) (*policy.CompiledProfile, error) {
		if cp, ok := compiled[version]; ok {
			return cp, nil
		}
		doc := f.Profiles[version]
		if doc == nil {
			return nil, fmt.Errorf("profile version %s is not in the grants file", short(version))
		}
		if v := doc.Version(); v != version {
			return nil, fmt.Errorf("profile %s reads back as version %s, not %s", doc.Metadata.Name, short(v), short(version))
		}
		if s.policy.Load() == nil {
			return nil, errors.New("the node agent has no policy loaded")
		}
		c, diags := policy.Compile(opts, doc)
		if len(diags) > 0 {
			return nil, fmt.Errorf("profile %s@%s no longer compiles here: %v", doc.Metadata.Name, short(version), diags[0])
		}
		compiled[version] = c.Profiles[0]
		return c.Profiles[0], nil
	}

	// Parents first: a nested run's chain must be live when it is bound.
	depth := func(g runGrant) int { return strings.Count(g.CgroupPath, "/") }
	sort.SliceStable(f.Runs, func(i, j int) bool { return depth(f.Runs[i]) < depth(f.Runs[j]) })
	for _, g := range f.Runs {
		path := filepath.Join(s.cm.GetAgentsDir(), g.CgroupPath)
		if g.CgroupPath == "" || strings.HasPrefix(g.CgroupPath, "..") || RunIDFromPath(path) != g.RunID {
			rep.Gone++
			continue
		}
		id, err := GetCgroupID(path)
		if err != nil || id != g.CgroupID {
			rep.Gone++ // ended, and perhaps a cgroup of another name since
			continue
		}
		if g.Parent != "" {
			s.mu.Lock()
			live := s.active[g.Parent]
			s.mu.Unlock()
			if !live {
				// A nested run whose parent was not restored: its
				// cgroup is inside the parent's, which the reaper
				// removes with it. Treat it as gone.
				rep.Gone++
				continue
			}
		}
		var eff *policy.Effective
		var why string
		if g.Profiled {
			eff = &policy.Effective{Ceiling: g.Ceiling}
			for _, gl := range g.Layers {
				var cp *policy.CompiledProfile
				var err error
				if gl.Builtin != "" {
					cp, err = policy.BuiltinProfile(gl.Builtin, gl.Message)
				} else {
					cp, err = profile(gl.Version)
				}
				if err != nil {
					why = err.Error()
					break
				}
				eff.Layers = append(eff.Layers, policy.Layer{Profile: cp, Source: gl.Source})
			}
			if why != "" || len(eff.Layers) == 0 {
				if why == "" {
					why = "no layers recorded"
				}
				msg := "Egress for this run was revoked: the node agent restarted and could not restore its policy (" + why + "). Start the run again."
				rev, _ := policy.BuiltinProfile(policy.BuiltinRevoked, msg)
				eff = &policy.Effective{Layers: []policy.Layer{{Profile: rev, Source: "node agent: not restored"}}, Ceiling: policy.NetGrant{}}
				rep.Revoked = append(rep.Revoked, g.RunID+": "+why)
			}
		}
		s.adopt(g, path, eff)
		rep.Restored++
	}
	s.saveGrants() // without the runs that ended meanwhile
	return rep, nil
}

// adopt binds a restored run as create binds a new one.
func (s *RunAPIServer) adopt(g runGrant, path string, eff *policy.Effective) {
	s.cm.AdoptRunCgroup(g.RunID, path)
	s.mu.Lock()
	s.active[g.RunID] = true
	s.restored[g.RunID] = time.Time{}
	s.creators[g.RunID] = g.Creator
	s.runByCg[g.CgroupID] = g.RunID
	s.runCg[g.RunID] = g.CgroupID
	if eff != nil {
		b := &boundRun{runID: g.RunID, uid: g.UID, cgroupID: g.CgroupID, eff: eff, started: g.Started}
		s.bound[g.RunID] = b
		s.byCg[g.CgroupID] = b
	}
	if g.Parent != "" {
		s.parentOf[g.RunID] = g.Parent
		s.children[g.Parent] = append(s.children[g.Parent], g.RunID)
	}
	s.mu.Unlock()

	m := g.Meta
	m.RunID, m.UID = g.RunID, g.UID
	m.Restored = append(m.Restored, time.Now().UTC())
	if eff != nil && len(eff.Layers) == 1 && eff.Layers[0].Source == "node agent: not restored" && m.Policy != nil {
		np := *m.Policy
		np.Layers = append(append([]PolicyLayer{}, m.Policy.Layers...), layerRecord(eff.Layers[0], time.Now().UTC()))
		m.Policy = &np
	}
	if g.Parent != "" {
		s.reg.PutNested(m, g.CgroupID)
	} else {
		s.reg.Put(m)
	}
	// Tool calls still open keep their attribution, and new calls their
	// numbering. Their clients are gone, so their cgroups go with the run.
	for _, c := range m.Calls {
		n := 0
		fmt.Sscanf(c.ID, "call-%d", &n)
		s.mu.Lock()
		if n > s.callSeq[g.RunID] {
			s.callSeq[g.RunID] = n
		}
		s.mu.Unlock()
		if c.EndedAt == nil {
			if id, err := GetCgroupID(filepath.Join(path, c.ID)); err == nil && id == c.CgroupID {
				s.addRunCgroup(g.RunID, c.CgroupID)
				s.reg.IndexCall(g.RunID, c)
			}
		}
	}
	if s.OnRunStart != nil {
		s.OnRunStart(g.RunID, g.CgroupID)
	}
	if eff != nil && s.OnPolicy != nil {
		if err := s.OnPolicy(g.CgroupID, g.UID, eff, g.Parent != ""); err != nil {
			log.Printf("run api: restored run %s: kernel policy: %v", g.RunID, err)
		}
	}
	if eff != nil && eff.CapturesTLS() {
		// The previous node agent may have died holding a process at
		// exec (milestone 6.2).
		if n := ContinueStopped(path); n > 0 {
			log.Printf("run api: restored run %s: continued %d stopped processes", g.RunID, n)
		}
	}
	what := "unprofiled"
	if eff != nil {
		var names []string
		for _, l := range eff.Layers {
			n := l.Profile.Name
			if l.Profile.Profile != nil && l.Profile.Builtin == "" {
				n += "@" + l.Profile.Profile.ShortVersion()
			}
			names = append(names, n)
		}
		what = strings.Join(names, ", ")
	}
	log.Printf("run api: run %s restored for uid %d: %s", g.RunID, g.UID, what)
}

func short(version string) string {
	if len(version) > 7+12 {
		return version[:7+12]
	}
	return version
}

// procIdentityOf reads a process's identity, or the zero value.
func procIdentityOf(pid int32) procIdentity {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return procIdentity{}
	}
	// The command is in parentheses and may hold spaces: fields count
	// from the last ')'.
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return procIdentity{}
	}
	fields := strings.Fields(string(b[i+1:]))
	// Field 22 overall is starttime; after the command, it is index 19.
	if len(fields) < 20 {
		return procIdentity{}
	}
	var start uint64
	fmt.Sscan(fields[19], &start)
	return procIdentity{PID: pid, Start: start}
}
