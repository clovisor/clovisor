// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build linux

package clovisor

import (
	"net"

	"golang.org/x/sys/unix"
)

// The run API on Linux: SOCK_SEQPACKET, one JSON message per datagram,
// with pidfds passed as SCM_RIGHTS.
const apiNet = "unixpacket"

type msgConn struct {
	c        *net.UnixConn
	buf, oob []byte
}

func newMsgConn(c *net.UnixConn) *msgConn {
	return &msgConn{c: c, buf: make([]byte, maxAPIMessage), oob: make([]byte, unix.CmsgSpace(4*4))}
}

// recv reads one message and any file descriptors sent with it. A
// truncated message returns errMsgTooLarge, with its descriptors closed.
func (m *msgConn) recv() ([]byte, []int, error) {
	n, oobn, flags, _, err := m.c.ReadMsgUnix(m.buf, m.oob)
	fds := parseFDs(m.oob[:oobn])
	if err != nil || n == 0 {
		closeFDs(fds)
		if err == nil {
			err = errEOF
		}
		return nil, nil, err
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		closeFDs(fds)
		return nil, nil, errMsgTooLarge
	}
	return m.buf[:n], fds, nil
}

func (m *msgConn) send(b []byte, fds ...int) error {
	var oob []byte
	if len(fds) > 0 {
		oob = unix.UnixRights(fds...)
	}
	_, _, err := m.c.WriteMsgUnix(b, oob, nil)
	return err
}

func parseFDs(oob []byte) []int {
	if len(oob) == 0 {
		return nil
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	var fds []int
	for _, m := range msgs {
		if got, err := unix.ParseUnixRights(&m); err == nil {
			fds = append(fds, got...)
		}
	}
	return fds
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		unix.Close(fd)
	}
}
