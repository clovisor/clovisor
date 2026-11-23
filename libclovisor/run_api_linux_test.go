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
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestProcHelpers(t *testing.T) {
	ppid, uid, err := procStatus(os.Getpid())
	if err != nil || ppid != os.Getppid() || uid != os.Getuid() {
		t.Fatalf("procStatus = %d, %d, %v; want %d, %d", ppid, uid, err, os.Getppid(), os.Getuid())
	}
	cg, err := procCgroup(os.Getpid())
	if err != nil || !strings.HasPrefix(cg, "/") {
		t.Fatalf("procCgroup = %q, %v", cg, err)
	}
}

func TestPidfdPid(t *testing.T) {
	pidfd := -1
	cmd := exec.Command("sleep", "5")
	cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start child: %v", err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	defer unix.Close(pidfd)

	pid, err := pidfdPid(pidfd)
	if err != nil || pid != cmd.Process.Pid {
		t.Fatalf("pidfdPid = %d, %v; want %d", pid, err, cmd.Process.Pid)
	}
	ppid, _, err := procStatus(pid)
	if err != nil || ppid != os.Getpid() {
		t.Fatalf("child ppid = %d, %v", ppid, err)
	}

	f, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := pidfdPid(int(f.Fd())); err == nil {
		t.Fatal("a regular file was accepted as a pidfd")
	}
}

func TestInetSockets(t *testing.T) {
	before, err := inetSockets(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	u, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	// A Unix socket is not a network socket.
	us, err := net.Listen("unix", t.TempDir()+"/s")
	if err != nil {
		t.Fatal(err)
	}
	defer us.Close()
	after, err := inetSockets(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if after-before != 2 {
		t.Fatalf("network sockets: %d before, %d after opening two", before, after)
	}
}

func TestUnixPolicyEncoding(t *testing.T) {
	p, err := unixPolicyOf([]string{"/run/x.sock", "/tmp/ssh-*", "@abc"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if p.N != 3 || p.Enforce != 1 || p.P[0].Len != 11 || p.P[0].Prefix != 0 || p.P[1].Len != 9 || p.P[1].Prefix != 1 ||
		string(p.P[2].B[:p.P[2].Len]) != "@abc" {
		t.Fatalf("%+v", p)
	}
	if _, err := unixPolicyOf(make([]string, 9), false); err == nil {
		t.Error("nine patterns accepted")
	}
}
