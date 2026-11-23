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
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/clovisor/clovisor/libclovisor/policy"
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

func TestExecHashMatchesLayout(t *testing.T) {
	// Same path, same hash; the padding is zero; a one-byte change moves it.
	h1, b := execHash("/usr/bin/git")
	h2, _ := execHash("/usr/bin/git")
	h3, _ := execHash("/usr/bin/gix")
	if h1 != h2 || h1 == h3 || string(b[:12]) != "/usr/bin/git" || b[12] != 0 {
		t.Fatalf("%x %x %x", h1, h2, h3)
	}
}

func TestNetPolicyOf(t *testing.T) {
	g := policy.NetGrant{
		UDP:  []netip.AddrPort{netip.MustParseAddrPort("10.0.0.5:5000"), netip.MustParseAddrPort("[fd00::1]:123")},
		ICMP: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("fd00::/60")},
	}
	p, err := netPolicyOf(g)
	if err != nil {
		t.Fatal(err)
	}
	if p.UDP[0].IP != netip.MustParseAddr("::ffff:10.0.0.5").As16() || p.UDP[0].Port != 5000 || p.UDP[1].Port != 123 || p.UDP[2].Port != 0 {
		t.Errorf("udp: %+v", p.UDP[:3])
	}
	// IPv4 /16: the mapped prefix and the first two octets, 96+16 bits.
	m := p.ICMP[0].Mask
	if m[9] != 0xff || m[13] != 0xff || m[14] != 0 || p.ICMP[0].IP[12] != 10 || p.ICMP[0].IP[13] != 1 {
		t.Errorf("icmp v4: %x %x", p.ICMP[0].IP, m)
	}
	// IPv6 /60: seven full bytes and a nibble.
	m = p.ICMP[1].Mask
	if m[6] != 0xff || m[7] != 0xf0 || m[8] != 0 {
		t.Errorf("icmp v6 mask: %x", m)
	}
	if p.ICMP[2].Mask != ([16]byte{}) {
		t.Error("unused entry has a mask")
	}
}
