// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build linux

package clovisor

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// probeEnvoy asks Envoy's admin socket whether it is ready and, if
// wantTransparent, whether it serves the transparent listener (an Envoy
// started before the node agent wrote that bootstrap does not). The admin
// socket's peer credentials name Envoy's process, hence its cgroup.
func probeEnvoy(admin string, wantTransparent bool) EnvoyState {
	var st EnvoyState
	if admin == "" {
		st.Err = fmt.Errorf("no Envoy admin socket configured")
		return st
	}
	c, err := net.DialTimeout("unix", admin, time.Second)
	if err != nil {
		st.Err = fmt.Errorf("Envoy admin socket: %w", err)
		return st
	}
	if raw, err := c.(*net.UnixConn).SyscallConn(); err == nil {
		raw.Control(func(fd uintptr) {
			if cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
				st.PID = int(cred.Pid)
			}
		})
	}
	c.Close()

	hc := &http.Client{Timeout: time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", admin)
		},
	}}
	get := func(path string) (string, int, error) {
		resp, err := hc.Get("http://envoy" + path)
		if err != nil {
			return "", 0, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return string(b), resp.StatusCode, err
	}
	if body, code, err := get("/ready"); err != nil || code != http.StatusOK {
		st.Err = fmt.Errorf("Envoy not ready: %d %s %v", code, strings.TrimSpace(body), err)
		return st
	}
	st.Ready = true
	if wantTransparent {
		body, _, err := get("/listeners")
		if err != nil {
			st.Err = fmt.Errorf("Envoy listeners: %w", err)
			return st
		}
		for _, l := range strings.Split(body, "\n") {
			if strings.HasPrefix(l, "transparent::") {
				st.Transparent = true
			}
		}
		if !st.Transparent {
			st.Err = fmt.Errorf("Envoy has no transparent listener: it runs a bootstrap from before transparent mode; restart it")
			return st
		}
	}
	if st.PID > 0 {
		st.Cgroup, _ = procCgroup(st.PID)
		st.Dedicated = dedicatedCgroup(st.Cgroup)
	}
	return st
}

// dedicatedCgroup reports whether every process in cgroup cg is Envoy,
// as in a Docker container or a systemd unit of its own. Only then may
// the proxy gate attach there: it applies to everything in the cgroup.
func dedicatedCgroup(cg string) bool {
	if cg == "" || cg == "/" {
		return false
	}
	data, err := os.ReadFile(filepath.Join(CgroupV2Root, cg, "cgroup.procs"))
	if err != nil {
		return false
	}
	n := 0
	for _, f := range strings.Fields(string(data)) {
		pid, err := strconv.Atoi(f)
		if err != nil {
			return false
		}
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue // exited
		}
		if strings.TrimSpace(string(comm)) != "envoy" {
			return false
		}
		n++
	}
	return n > 0
}
