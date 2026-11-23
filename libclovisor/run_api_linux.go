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
	// Checked after the move: a socket the process creates from now on
	// is in the run, so none can slip in between check and move.
	if ac.s.Transparent == TransparentEnforce || ac.s.Transparent == TransparentAudit {
		n, err := inetSockets(pid)
		switch {
		case err != nil && ac.s.Transparent == TransparentEnforce:
			unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
			return fail("cannot check pid %d for network sockets: %v", pid, err)
		case n > 0 && ac.s.Transparent == TransparentEnforce:
			unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
			return fail("pid %d holds %d network sockets created outside the run; they would bypass transparent mode. "+
				"Start the run from a process without open network sockets", pid, n)
		case n > 0:
			log.Printf("run api: run %s: pid %d holds %d network sockets created outside the run (would be refused in enforce)", ac.runID, pid, n)
		}
	}
	ac.attached = true
	return RunAPIResponse{OK: true, RunID: ac.runID}
}

// inetSockets counts the TCP, UDP and raw sockets among pid's open files:
// socket inodes of its fd table that appear in its network namespace's
// /proc/net tables.
func inetSockets(pid int) (int, error) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	ents, err := os.ReadDir(fdDir)
	if err != nil {
		return 0, err
	}
	socks := map[string]bool{}
	for _, e := range ents {
		t, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue // closed meanwhile
		}
		if ino, ok := strings.CutPrefix(t, "socket:["); ok {
			socks[strings.TrimSuffix(ino, "]")] = true
		}
	}
	if len(socks) == 0 {
		return 0, nil
	}
	n := 0
	for _, tbl := range []string{"tcp", "tcp6", "udp", "udp6", "raw", "raw6", "udplite", "udplite6"} {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/%s", pid, tbl))
		if err != nil {
			if os.IsNotExist(err) {
				continue // e.g. no IPv6
			}
			return 0, err
		}
		lines := strings.Split(string(data), "\n")
		for _, l := range lines[1:] {
			f := strings.Fields(l)
			// sl local remote st tx:rx tr:when retrnsmt uid timeout inode
			if len(f) > 9 && socks[f[9]] {
				n++
			}
		}
	}
	return n, nil
}

// attachCall moves the process behind pidfd into the call opened on this
// connection. It must be a child of the caller, of the caller's uid, and
// already inside the same run: a call can only subdivide a run, never let
// anything in.
func (ac *apiConn) attachCall(pidfd int) RunAPIResponse {
	if ac.attached {
		return fail("call %s already has its process", ac.callID)
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
	cg, err := procCgroup(pid)
	if err != nil || ac.s.runOfCgroupPath(cg) != ac.callRun {
		return fail("pid %d is not in run %s", pid, ac.callRun)
	}
	if err := os.WriteFile(filepath.Join(ac.callPath, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0); err != nil {
		return fail("failed to move pid %d into call: %v", pid, err)
	}
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		return fail("process exited during attach")
	}
	ac.attached = true
	return RunAPIResponse{OK: true, RunID: ac.callRun, CallID: ac.callID}
}
