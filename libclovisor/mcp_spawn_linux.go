// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build linux

package clovisor

import "syscall"

// serverProcAttr starts an MCP server in its own session, as cred if set,
// and directly into the cgroup cgFD if not -1 (CLONE_INTO_CGROUP).
func serverProcAttr(cred *syscall.Credential, cgFD int) *syscall.SysProcAttr {
	a := &syscall.SysProcAttr{Credential: cred, Setsid: true}
	if cgFD >= 0 {
		a.UseCgroupFD, a.CgroupFD = true, cgFD
	}
	return a
}
