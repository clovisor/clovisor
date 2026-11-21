// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build linux

package clovisor

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// peerInfo is a run API caller's kernel credentials.
type peerInfo struct {
	Uid, Gid uint32
	Pid      int32
}

func peerCred(c *net.UnixConn) (*peerInfo, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	if serr != nil {
		return nil, serr
	}
	return &peerInfo{Uid: cred.Uid, Gid: cred.Gid, Pid: cred.Pid}, nil
}

// groups returns the caller's supplementary groups, from the kernel's
// view of the calling process.
func (p *peerInfo) groups() ([]int, error) { return procGroups(int(p.Pid)) }

// procCgroup returns a process's cgroup v2 path, e.g. /user.slice/x.scope.
func procCgroup(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::"), nil
		}
	}
	return "", fmt.Errorf("pid %d has no cgroup v2 membership", pid)
}

// procStatus returns the parent pid and real uid of a process.
func procStatus(pid int) (ppid int, uid int, err error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	ppid, uid = -1, -1
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(v)
		if len(fields) == 0 {
			continue
		}
		switch k {
		case "PPid":
			ppid, _ = strconv.Atoi(fields[0])
		case "Uid":
			uid, _ = strconv.Atoi(fields[0])
		}
	}
	if ppid < 0 || uid < 0 {
		return 0, 0, fmt.Errorf("cannot parse /proc/%d/status", pid)
	}
	return ppid, uid, sc.Err()
}

// pidfdPid returns the pid a pidfd refers to.
func pidfdPid(fd int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "Pid:"); ok {
			pid, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || pid <= 0 {
				return 0, fmt.Errorf("fd %d is not a live pidfd", fd)
			}
			return pid, nil
		}
	}
	return 0, fmt.Errorf("fd %d is not a pidfd", fd)
}

// procGroups returns a process's supplementary groups.
func procGroups(pid int) ([]int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "Groups:"); ok {
			var gs []int
			for _, f := range strings.Fields(v) {
				g, err := strconv.Atoi(f)
				if err != nil {
					return nil, err
				}
				gs = append(gs, g)
			}
			return gs, nil
		}
	}
	return nil, nil
}

// attach moves the process behind pidfd into the run. The process must be
// a direct child of the caller, have the caller's real uid, and not
// already be in a run.
func (ac *apiConn) attach(pidfd int) RunAPIResponse {
	if ac.runID == "" {
		return fail("no run: send create first")
	}
	if ac.attached {
		return fail("run %s already has its process", ac.runID)
	}
	pid, err := pidfdPid(pidfd)
	if err != nil {
		return fail("%v", err)
	}
	ppid, uid, err := procStatus(pid)
	if err != nil {
		return fail("%v", err)
	}
	if ppid != int(ac.cred.Pid) {
		return fail("pid %d is not a child of the caller", pid)
	}
	if uid != int(ac.cred.Uid) {
		return fail("pid %d does not belong to uid %d", pid, ac.cred.Uid)
	}
	if cg, err := procCgroup(pid); err != nil || ac.s.inAgents(cg) {
		return fail("pid %d is already in a run, or its cgroup is unreadable", pid)
	}

	if err := os.WriteFile(filepath.Join(ac.runPath, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0); err != nil {
		return fail("failed to move pid %d into run: %v", pid, err)
	}
	// The pid cannot have been reused between the checks and the move
	// while the pidfd's process is alive: an unreaped process keeps its
	// pid. Confirm it still is.
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		log.Printf("run api: run %s: process %d exited during attach; the pid may have been reused", ac.runID, pid)
		return fail("process exited during attach")
	}
	ac.attached = true
	return RunAPIResponse{OK: true, RunID: ac.runID}
}
