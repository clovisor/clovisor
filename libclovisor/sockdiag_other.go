// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build !linux

package clovisor

import (
	"errors"
	"net/netip"
)

// SockCgroup needs Linux socket diagnostics. Elsewhere runs are
// identified by their proxy credential instead.
func SockCgroup(local, remote netip.AddrPort) (uint64, error) {
	return 0, errors.New("socket cgroup lookup needs Linux; use credential identity")
}
