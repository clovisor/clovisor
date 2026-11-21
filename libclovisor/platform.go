// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"errors"
	"io"
)

// Platform notes. Kernel-backed pieces (BPF audit, cgroups, socket
// diagnostics, SO_PEERCRED, pidfds) are in *_linux.go files, with stubs
// in *_other.go. Off Linux, and on Linux with -identity credential, the
// node agent identifies runs by a per-run proxy credential (design §4.3):
// a claim, not an enforcement-grade identity.

// ErrSockNotFound means no socket has that 4-tuple.
var ErrSockNotFound = errors.New("socket not found")

var (
	errMsgTooLarge = errors.New("message too large")
	errEOF         = io.EOF
)
