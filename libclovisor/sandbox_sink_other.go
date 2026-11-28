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
	"sync/atomic"
)

// SandboxSink receives gVisor sandboxes' points; gVisor runs only on
// Linux.
type SandboxSink struct {
	Dir, ActorsDir string
	Out            func(SandboxEvent)
	PeerArgs       func(pid int32) ([]string, error)

	Accepted, Refused atomic.Uint64
}

func (s *SandboxSink) Listen() error { return errors.New("the sandbox sink needs Linux") }
func (s *SandboxSink) Serve() error  { return errors.New("the sandbox sink needs Linux") }
func (s *SandboxSink) Close()        {}
