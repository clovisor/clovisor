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

func NewEBPFReader(bpfObjPath, agentsDir string, agentsCgroupID uint64, agentsLevel uint32, t TransparentOptions) (*EBPFReader, error) {
	return nil, errors.New("kernel audit (BPF) needs Linux")
}

func (r *EBPFReader) Start() error                               { return nil }
func (r *EBPFReader) Stop() error                                { return nil }
func (r *EBPFReader) Events() <-chan AuditEvent                  { return nil }
func (r *EBPFReader) Close()                                     {}
func (r *EBPFReader) SetHealth(func() error)                     {}
func (r *EBPFReader) Healthy() bool                              { return false }
func (r *EBPFReader) LostFor(uint64) (uint64, uint64)            { return 0, 0 }
func (r *EBPFReader) LostTotal() (uint64, uint64)                { return 0, 0 }
func (r *EBPFReader) ProxyRefused() uint64                       { return 0 }
func (r *EBPFReader) GateProxy(string) error                     { return errors.New("needs Linux") }
func (r *EBPFReader) GatedProxy() string                         { return "" }
func (r *EBPFReader) LSMState() string                           { return "needs Linux" }
func (r *EBPFReader) SetUnixPolicy(uint64, []string, bool) error { return nil }
func (r *EBPFReader) ForgetUnixPolicy(uint64)                    {}
func (r *EBPFReader) SetUnixNode([]string) error                 { return nil }

// BPFLSMActive is false off Linux.
func BPFLSMActive() bool { return false }
