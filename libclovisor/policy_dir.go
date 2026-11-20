// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// DefaultPolicyDir holds the profiles and ceilings the node agent serves.
const DefaultPolicyDir = "/etc/clovisor/policy"

// checkTrusted refuses a policy path anyone but root could have written.
// Ceilings decide who gets which profile; a user able to write one could
// grant themselves anything.
func checkTrusted(path string, wantDir, requireRoot bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("%s is a symlink; policy files must be regular files", path)
	case wantDir && !fi.IsDir():
		return fmt.Errorf("%s is not a directory", path)
	case !wantDir && !fi.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file", path)
	case fi.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%s is writable by group or others (mode %v)", path, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && requireRoot && st.Uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, not root", path, st.Uid)
	}
	return nil
}

func lookupUID(name string) (int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(u.Uid)
}

func lookupGID(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}

// LoadPolicyDir loads every *.yaml and *.yml file in dir: AgentProfiles and
// ProfileCeilings, compiled together, since TLS posture is node-wide. With
// requireRoot, dir and every file must be owned by root.
func LoadPolicyDir(dir string, opts policy.Options, requireRoot bool) (*policy.Set, error) {
	if err := checkTrusted(dir, true, requireRoot); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if n := e.Name(); strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml") {
			names = append(names, n)
		}
	}
	sort.Strings(names)

	var profiles []*policy.AgentProfile
	var ceilings []*policy.ProfileCeiling
	var errs []string
	for _, n := range names {
		path := filepath.Join(dir, n)
		if err := checkTrusted(path, false, requireRoot); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		p, c, err := policy.ParseDocument(data)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		if p != nil {
			profiles = append(profiles, p)
		} else {
			ceilings = append(ceilings, c)
		}
	}
	if len(errs) == 0 {
		set, diags := policy.NewSet(opts, profiles, ceilings, lookupUID, lookupGID)
		for _, d := range diags {
			errs = append(errs, d.Error())
		}
		if len(errs) == 0 {
			return set, nil
		}
	}
	return nil, errors.New("policy " + dir + ":\n  " + strings.Join(errs, "\n  "))
}
