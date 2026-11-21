// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build !linux

package clovisor

import "errors"

// EBPFReader is Linux-only. Elsewhere the node agent runs with
// credential identity and no kernel audit (design §4.3).
type EBPFReader struct{}

func NewEBPFReader(bpfObjPath, agentsDir string, agentsCgroupID uint64, agentsLevel uint32) (*EBPFReader, error) {
	return nil, errors.New("kernel audit (BPF) needs Linux")
}

func (r *EBPFReader) Start() error              { return nil }
func (r *EBPFReader) Stop() error               { return nil }
func (r *EBPFReader) Events() <-chan AuditEvent { return nil }
func (r *EBPFReader) Close()                    {}
