// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build darwin

package clovisor

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// peerInfo is a run API caller's credentials, from LOCAL_PEERCRED and
// LOCAL_PEERPID.
type peerInfo struct {
	Uid, Gid uint32
	Pid      int32
	groupIDs []int
}

func peerCred(c *net.UnixConn) (*peerInfo, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var x *unix.Xucred
	var pid int
	var serr, perr error
	if err := raw.Control(func(fd uintptr) {
		x, serr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		pid, perr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil {
		return nil, err
	}
	if serr != nil {
		return nil, serr
	}
	p := &peerInfo{Uid: x.Uid}
	if perr == nil {
		p.Pid = int32(pid)
	}
	for i := 0; i < int(x.Ngroups) && i < len(x.Groups); i++ {
		p.groupIDs = append(p.groupIDs, int(x.Groups[i]))
	}
	if len(p.groupIDs) > 0 {
		p.Gid = uint32(p.groupIDs[0])
	}
	return p, nil
}

func (p *peerInfo) groups() ([]int, error) { return p.groupIDs, nil }

func procCgroup(pid int) (string, error) { return "", errors.New("cgroups need Linux") }

func (ac *apiConn) attach(pidfd int) RunAPIResponse {
	return fail("attach needs Linux cgroups; with credential identity the client starts the run's process itself")
}

func (ac *apiConn) attachCall(pidfd int) RunAPIResponse {
	return fail("tool calls need Linux cgroups")
}
