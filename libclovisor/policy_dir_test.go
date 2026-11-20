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
	"testing"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

const testProfile = `kind: AgentProfile
metadata: { name: light }
spec:
  mode: enforce
  egress: { default: deny, rules: [ { name: gh, to: { fqdn: ["github.com"] }, action: allow } ] }
`

const testCeiling = `kind: ProfileCeiling
metadata: { name: everyone }
spec: { appliesTo: { any: true }, allow: [light], default: light }
`

func writePolicy(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadPolicyDir(t *testing.T) {
	dir := writePolicy(t, map[string]string{"light.yaml": testProfile, "ceiling.yml": testCeiling, "README": "ignored"})
	set, err := LoadPolicyDir(dir, policy.Options{Linux: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := set.Resolve(policy.Caller{UID: 1234}, "")
	if err != nil || b.Granted().Name != "light" {
		t.Fatalf("resolve: %v %v", b, err)
	}

	// Ownership is enforced when asked (tests run as a normal user).
	if os.Getuid() != 0 {
		if _, err := LoadPolicyDir(dir, policy.Options{}, true); err == nil || !strings.Contains(err.Error(), "not root") {
			t.Errorf("non-root-owned dir accepted: %v", err)
		}
	}
}

func TestLoadPolicyDirRefusesWritableAndSymlinks(t *testing.T) {
	dir := writePolicy(t, map[string]string{"light.yaml": testProfile, "ceiling.yaml": testCeiling})
	os.Chmod(filepath.Join(dir, "ceiling.yaml"), 0o666)
	if _, err := LoadPolicyDir(dir, policy.Options{}, false); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Errorf("world-writable ceiling accepted: %v", err)
	}

	dir = writePolicy(t, map[string]string{"light.yaml": testProfile})
	outside := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(outside, []byte(testCeiling), 0o644)
	os.Symlink(outside, filepath.Join(dir, "ceiling.yaml"))
	if _, err := LoadPolicyDir(dir, policy.Options{}, false); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("symlinked ceiling accepted: %v", err)
	}

	dir = writePolicy(t, map[string]string{"light.yaml": testProfile})
	os.Chmod(dir, 0o777)
	if _, err := LoadPolicyDir(dir, policy.Options{}, false); err == nil {
		t.Error("world-writable directory accepted")
	}

	dir = writePolicy(t, map[string]string{"bad.yaml": "kind: AgentProfile\nmetadata: {name: x}\nspec: {mode: enforce, egress: {default: deny, rules: [{name: d, to: {fqdn: [a.com]}, action: deny}]}}\n"})
	if _, err := LoadPolicyDir(dir, policy.Options{}, false); err == nil || !strings.Contains(err.Error(), "needs a message") {
		t.Errorf("compile error not reported: %v", err)
	}
}
