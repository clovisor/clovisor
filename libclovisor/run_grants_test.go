// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

const grantProfile = `kind: AgentProfile
metadata: { name: g }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - { name: gh, to: { fqdn: ["github.com"], ports: [443] }, action: allow }
      - { name: pypi, to: { fqdn: ["pypi.org"], ports: [443] }, action: allow }
`

const grantCeiling = `kind: ProfileCeiling
metadata: { name: all }
spec:
  appliesTo: { any: true }
  allow: [g, narrow]
  default: g
`

const narrowProfile = `kind: AgentProfile
metadata: { name: narrow }
spec:
  mode: enforce
  egress:
    default: deny
    rules:
      - { name: gh, to: { fqdn: ["github.com"], ports: [443] }, action: allow }
`

func grantSet(t *testing.T, docs ...string) *policy.Set {
	t.Helper()
	var ps []*policy.AgentProfile
	var cs []*policy.ProfileCeiling
	for _, d := range docs {
		p, c, err := policy.ParseDocument([]byte(d))
		if err != nil {
			t.Fatal(err)
		}
		if p != nil {
			ps = append(ps, p)
		}
		if c != nil {
			cs = append(cs, c)
		}
	}
	set, diags := policy.NewSet(policy.Options{Linux: true}, ps, cs, nil, nil)
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	return set
}

// fakeRunCgroup makes a directory standing in for a run cgroup, with a
// cgroup.events saying whether it is populated.
func fakeRunCgroup(t *testing.T, path string, populated bool) uint64 {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	setPopulated(t, path, populated)
	id, err := GetCgroupID(path)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func setPopulated(t *testing.T, path string, populated bool) {
	v := "0"
	if populated {
		v = "1"
	}
	if err := os.WriteFile(filepath.Join(path, "cgroup.events"), []byte("populated "+v+"\nfrozen 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func grantServer(t *testing.T, agents, state string, set *policy.Set) *RunAPIServer {
	t.Helper()
	cm := &CgroupManager{root: agents, agents: agents, runMap: map[string]string{}}
	s, err := NewRunAPIServer(filepath.Join(t.TempDir(), "agent.sock"), cm, NewRunRegistry())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.ln.Close() })
	s.GrantsPath = filepath.Join(state, "grants.json")
	s.SetPolicy(set)
	return s
}

// bindFake binds a run as create does, without a client.
func bindFake(s *RunAPIServer, runID, path string, cg uint64, parent string, eff *policy.Effective, uid int) {
	s.cm.AdoptRunCgroup(runID, path)
	s.mu.Lock()
	s.active[runID] = true
	s.creators[runID] = procIdentityOf(int32(os.Getpid()))
	s.runByCg[cg], s.runCg[runID] = runID, cg
	if eff != nil {
		b := &boundRun{runID: runID, uid: uid, cgroupID: cg, eff: eff, started: time.Now().Add(-time.Minute)}
		s.bound[runID], s.byCg[cg] = b, b
	}
	if parent != "" {
		s.parentOf[runID] = parent
		s.children[parent] = append(s.children[parent], runID)
	}
	s.mu.Unlock()
	var rp *RunPolicy
	if eff != nil {
		rp = &RunPolicy{Ceiling: "all"}
		for _, l := range eff.Layers {
			rp.Layers = append(rp.Layers, layerRecord(l, time.Now()))
		}
	}
	m := RunMeta{RunID: runID, Command: []string{"agent"}, UID: uid, StartedAt: time.Now(), Policy: rp, Parent: parent,
		Calls: []CallMeta{{ID: "call-3", CgroupID: 999}}}
	if parent != "" {
		s.reg.PutNested(m, cg)
	} else {
		s.reg.Put(m)
	}
	s.saveGrants()
}

func allowed(eff *policy.Effective, host string) bool {
	return eff.Decide(policy.Request{Host: host, Port: 443}).Allowed()
}

// Runs that outlive the node agent get back what they were granted: the
// version they were bound to, clamps, revocations and nesting, in the
// kernel too. Runs whose grants cannot be rebuilt are revoked; runs that
// ended meanwhile are dropped (milestone 6.1).
func TestRestoreGrants(t *testing.T) {
	agents, state := t.TempDir(), t.TempDir()
	set := grantSet(t, grantProfile, narrowProfile, grantCeiling)
	s1 := grantServer(t, agents, state, set)
	b, err := set.Resolve(policy.Caller{UID: 1000}, "g")
	if err != nil {
		t.Fatal(err)
	}

	pa := filepath.Join(agents, "run-a")
	ida := fakeRunCgroup(t, pa, true)
	bindFake(s1, "a", pa, ida, "", b.Effective, 1000)
	pb := filepath.Join(pa, "run-b") // nested in a, with narrow too
	idb := fakeRunCgroup(t, pb, true)
	nb, _ := set.Resolve(policy.Caller{UID: 1000}, "narrow")
	bindFake(s1, "b", pb, idb, "a", policy.Nested(b.Effective, nb.Effective), 1000)
	pc := filepath.Join(agents, "run-c") // revoked
	idc := fakeRunCgroup(t, pc, true)
	bindFake(s1, "c", pc, idc, "", b.Effective, 1000)
	if _, err := s1.applyLayer("c", policy.Layer{Profile: policy.RevokedProfile(), Source: "revoked by uid 1000"}, nil); err != nil {
		t.Fatal(err)
	}
	pu := filepath.Join(agents, "run-u") // unprofiled
	idu := fakeRunCgroup(t, pu, false)
	bindFake(s1, "u", pu, idu, "", nil, 1000)
	pg := filepath.Join(agents, "run-gone") // ends while the node agent is down
	idg := fakeRunCgroup(t, pg, true)
	bindFake(s1, "gone", pg, idg, "", b.Effective, 1000)
	pd := filepath.Join(agents, "run-d") // its profile document is lost
	idd := fakeRunCgroup(t, pd, true)
	bindFake(s1, "d", pd, idd, "", b.Effective, 1000)

	// The grants file is root's alone, and holds each version once.
	st, err := os.Stat(s1.GrantsPath)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("grants file: %v %v", st, err)
	}
	var f grantFile
	raw, _ := os.ReadFile(s1.GrantsPath)
	if err := json.Unmarshal(raw, &f); err != nil || len(f.Runs) != 6 || len(f.Profiles) != 2 {
		t.Fatalf("grants: %d runs, %d profiles, %v", len(f.Runs), len(f.Profiles), err)
	}
	// Damage run d's record: a version the file does not hold.
	for i := range f.Runs {
		if f.Runs[i].RunID == "d" {
			f.Runs[i].Layers[0].Version = "sha256:" + strings.Repeat("0", 64)
		}
	}
	raw, _ = json.Marshal(f)
	os.WriteFile(s1.GrantsPath, raw, 0o600)
	os.RemoveAll(pg)

	// The node agent restarts with an edited profile: g no longer allows
	// pypi. Runs keep the version they were bound to.
	edited := strings.Replace(grantProfile, "      - { name: pypi, to: { fqdn: [\"pypi.org\"], ports: [443] }, action: allow }\n", "", 1)
	s2 := grantServer(t, agents, state, grantSet(t, edited, narrowProfile, grantCeiling))
	type pol struct {
		eff    *policy.Effective
		nested bool
	}
	kernel := map[uint64]pol{}
	s2.OnPolicy = func(cg uint64, uid int, eff *policy.Effective, nested bool) error {
		kernel[cg] = pol{eff, nested}
		return nil
	}
	started := map[string]bool{}
	s2.OnRunStart = func(runID string, cg uint64) { started[runID] = true }
	rep, err := s2.Restore()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Restored != 5 || rep.Gone != 1 || len(rep.Revoked) != 1 || !strings.HasPrefix(rep.Revoked[0], "d: ") {
		t.Fatalf("report: %+v", rep)
	}
	if _, _, eff, ok := s2.RunFor(ida); !ok || eff == nil || !allowed(eff, "pypi.org") || !allowed(eff, "github.com") || allowed(eff, "x.org") {
		t.Errorf("run a lost its bound version: %+v", eff)
	}
	if _, _, eff, _ := s2.RunFor(idb); eff == nil || allowed(eff, "pypi.org") || !allowed(eff, "github.com") || !kernel[idb].nested {
		t.Errorf("nested run b: %+v, kernel %+v", eff, kernel[idb])
	}
	if s2.parentOf["b"] != "a" || len(s2.children["a"]) != 1 {
		t.Errorf("nesting: %v %v", s2.parentOf, s2.children)
	}
	if _, _, eff, _ := s2.RunFor(idc); eff == nil || allowed(eff, "github.com") {
		t.Errorf("revoked run c came back with egress")
	}
	if _, _, eff, _ := s2.RunFor(idd); eff == nil || allowed(eff, "github.com") ||
		!strings.Contains(eff.Decide(policy.Request{Host: "github.com", Port: 443}).Message, "could not restore its policy") {
		t.Errorf("unrestorable run d not revoked with a reason")
	}
	if runID, _, eff, ok := s2.RunFor(idu); !ok || runID != "u" || eff != nil {
		t.Errorf("unprofiled run u: %s %v %v", runID, eff, ok)
	}
	if _, ok, _, _ := s2.RunFor(idg); ok != 0 {
		t.Errorf("a run that ended meanwhile came back")
	}
	if kernel[ida].eff == nil || kernel[idc].eff == nil || !started["a"] || !started["u"] {
		t.Errorf("kernel and limiter not told: %v %v", kernel, started)
	}
	if m, ok := s2.reg.Get("a"); !ok || len(m.Restored) != 1 || m.Command[0] != "agent" {
		t.Errorf("registry: %+v", m)
	}
	if s2.callSeq["a"] != 3 {
		t.Errorf("call numbering not resumed: %d", s2.callSeq["a"])
	}
	if s2.ActiveRuns() != 5 {
		t.Errorf("active runs %d", s2.ActiveRuns())
	}
	// The rewritten file no longer lists the run that ended.
	raw, _ = os.ReadFile(s2.GrantsPath)
	if strings.Contains(string(raw), `"run_id": "gone"`) {
		t.Error("grants still list the run that ended")
	}

	// Only the agentctl that created a run can claim it to report its end.
	other := &apiConn{s: s2, cred: &peerInfo{Pid: 1}}
	if err := other.claim("a"); err == nil {
		t.Error("another process claimed run a")
	}
	me := &apiConn{s: s2, cred: &peerInfo{Pid: int32(os.Getpid())}}
	if err := me.claim("a"); err != nil || me.runID != "a" {
		t.Errorf("creator could not claim run a: %v", err)
	}
	if err := me.claim("a"); err == nil {
		t.Error("run a claimed twice")
	}

	// An unclaimed run is ended once its cgroup has been empty a while.
	s2.endUnclaimed()
	s2.mu.Lock()
	s2.restored["u"] = time.Now().Add(-restoredGrace - time.Second)
	s2.mu.Unlock()
	s2.endUnclaimed()
	if s2.ActiveRuns() != 4 {
		t.Errorf("empty unclaimed run u not ended: %d active", s2.ActiveRuns())
	}
	s2.endUnclaimed() // populated runs stay
	if s2.ActiveRuns() != 4 {
		t.Errorf("populated runs ended: %d active", s2.ActiveRuns())
	}
}

// A grants file someone else can write is refused, not trusted.
func TestGrantsFileMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "grants.json")
	os.WriteFile(p, []byte(`{"version":1}`), 0o666)
	os.Chmod(p, 0o666)
	if _, err := PendingGrants(p); err == nil {
		t.Error("world-writable grants file accepted")
	}
	if n, err := PendingGrants(filepath.Join(t.TempDir(), "none")); err != nil || n != 0 {
		t.Errorf("missing file: %d %v", n, err)
	}
}
