// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build linux

package clovisor

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// TestBPFLoad loads each program of the audit BPF object on its own
// against the running kernel (milestone 7.2): the kernel matrix in CI
// runs it in a VM per kernel. A program must load on every kernel at or
// above the version the operator guide documents for it; below, its
// failure is reported, not failed. CLOVISOR_BPF_LOAD names the object
// (root needed).
func TestBPFLoad(t *testing.T) {
	obj := os.Getenv("CLOVISOR_BPF_LOAD")
	if obj == "" {
		t.Skip("CLOVISOR_BPF_LOAD unset: names the BPF object to load (needs root)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Logf("memlock: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		t.Fatal(err)
	}
	var u unix.Utsname
	unix.Uname(&u)
	release := unix.ByteSliceToString(u.Release[:])
	have := kernelVersion(release)
	t.Logf("kernel %s, BPF LSM active: %v", release, bpfLSMActiveHere())

	names := make([]string, 0, len(spec.Programs))
	for n := range spec.Programs {
		names = append(names, n)
	}
	sort.Strings(names)
	var failed, below []string
	for _, n := range names {
		ps := spec.Programs[n]
		need := minKernel(ps.SectionName)
		one := spec.Copy()
		for m := range one.Programs {
			if m != n {
				delete(one.Programs, m)
			}
		}
		coll, err := ebpf.NewCollectionWithOptions(one, ebpf.CollectionOptions{})
		if err == nil {
			coll.Close()
			t.Logf("ok      %-26s %s", n, ps.SectionName)
			continue
		}
		// The verifier's last lines say why: its very last is statistics.
		var ve *ebpf.VerifierError
		msg := err.Error()
		if errors.As(err, &ve) && len(ve.Log) > 0 {
			tail := ve.Log[max(0, len(ve.Log)-20):]
			msg = ve.Cause.Error() + "\n\t" + strings.Join(tail, "\n\t")
		}
		if have < need {
			below = append(below, n)
			t.Logf("below   %-26s %s (needs %s): %s", n, ps.SectionName, fmtVersion(need), msg)
			continue
		}
		failed = append(failed, n)
		t.Errorf("FAILED  %-26s %s (needs %s, have %s): %s", n, ps.SectionName, fmtVersion(need), release, msg)
	}
	t.Logf("%d programs: %d failed, %d not loaded on a kernel below their documented minimum", len(names), len(failed), len(below))
}

// minKernel is the version the operator guide documents for a program's
// section (§11 Kernel requirements), as major<<16 | minor<<8.
func minKernel(section string) int {
	switch {
	case strings.HasPrefix(section, "uprobe.multi"), strings.HasPrefix(section, "uretprobe.multi"):
		return 6<<16 | 6<<8 // TLS plaintext (-uprobes)
	case strings.HasPrefix(section, "lsm.s/"):
		return 5<<16 | 19<<8 // exec hashes: bpf_ima_file_hash (5.18), the TAI clock (5.19)
	case section == "cgroup/getsockopt":
		// Transparent mode: the cgroup ancestor helper in a getsockopt
		// program is refused on 5.15 and allowed on 6.1 (7.2's matrix).
		return 6<<16 | 1<<8
	}
	return 5<<16 | 12<<8 // the floor
}

func kernelVersion(release string) int {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0
	}
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(strings.TrimLeftFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' }))
	if i := strings.IndexFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		minor, _ = strconv.Atoi(parts[1][:i])
	}
	return major<<16 | minor<<8
}

func fmtVersion(v int) string { return fmt.Sprintf("%d.%d", v>>16, v>>8&0xff) }

func bpfLSMActiveHere() bool {
	b, _ := os.ReadFile("/sys/kernel/security/lsm")
	return strings.Contains(","+strings.TrimSpace(string(b))+",", ",bpf,")
}
