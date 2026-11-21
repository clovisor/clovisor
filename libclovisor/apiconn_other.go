// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build !linux

package clovisor

import (
	"bufio"
	"errors"
	"net"
)

// The run API off Linux: no SOCK_SEQPACKET on macOS, so a stream socket
// carrying one JSON message per line. JSON never contains a raw newline.
// No file descriptors cross it: there is no attach without cgroups.
const apiNet = "unix"

type msgConn struct {
	c *net.UnixConn
	r *bufio.Reader
}

func newMsgConn(c *net.UnixConn) *msgConn {
	return &msgConn{c: c, r: bufio.NewReaderSize(c, maxAPIMessage)}
}

func (m *msgConn) recv() ([]byte, []int, error) {
	line, err := m.r.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		// Skip the rest of the oversized line, then report it.
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = m.r.ReadSlice('\n')
		}
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, errMsgTooLarge
	case err != nil:
		return nil, nil, err
	}
	return line[:len(line)-1], nil, nil
}

func (m *msgConn) send(b []byte, fds ...int) error {
	if len(fds) > 0 {
		return errors.New("file descriptor passing needs Linux")
	}
	_, err := m.c.Write(append(append([]byte(nil), b...), '\n'))
	return err
}

func closeFDs(fds []int) {}
