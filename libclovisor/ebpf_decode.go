// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bytes"
	"fmt"
	"syscall"
)

// Decoding helpers for BPF records, kept portable so they are tested
// everywhere.

// cString returns b up to its first NUL.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// splitArgs splits a NUL-separated argv block. A block cut off at the
// capture limit keeps its partial last argument.
func splitArgs(b []byte) []string {
	b = bytes.TrimRight(b, "\x00")
	if len(b) == 0 {
		return nil
	}
	parts := bytes.Split(b, []byte{0})
	args := make([]string, len(parts))
	for i, p := range parts {
		args[i] = string(p)
	}
	return args
}

// socketFamily names an address family.
func socketFamily(f uint16) string {
	switch f {
	case 1:
		return "unix"
	case 2:
		return "inet"
	case 10:
		return "inet6"
	case 16:
		return "netlink"
	case 17:
		return "packet"
	case 29:
		return "can"
	case 31:
		return "bluetooth"
	case 40:
		return "vsock"
	case 44:
		return "xdp"
	}
	return fmt.Sprintf("family %d", f)
}

// ipProtoName names an IP protocol number.
func ipProtoName(p uint32) string {
	switch p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	}
	return fmt.Sprintf("proto %d", p)
}

func protoName(p uint32) string {
	switch p {
	case syscall.IPPROTO_TCP:
		return "TCP"
	case syscall.IPPROTO_UDP:
		return "UDP"
	default:
		return fmt.Sprintf("proto-%d", p)
	}
}
