// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	pb "github.com/clovisor/clovisor/libclovisor/gvisorpoints"
)

// Sandbox points are in Linux's ABI (gVisor is Linux), so this is the
// sink's side, which runs where the sandboxes do.

// SandboxSink receives the points of the gVisor sandboxes on a node
// (milestone 7.5). Each sandbox connects to its socket as runsc creates or
// restores it; the sink knows the Actor by that runsc's -root, and passes
// each point to Out. A sandbox does not start unless the sink is up and
// accepts it.
type SandboxSink struct {
	// Dir holds the socket and the trace session (runsc
	// --pod-init-config=<Dir>/session.json). On Substrate it is below
	// /var/lib/ate, which Worker pods mount from the node.
	Dir string
	// ActorsDir is where Substrate keeps each Actor's directory, named by
	// its UID (/var/lib/ate/actors).
	ActorsDir string
	Out       func(SandboxEvent)
	// PeerArgs returns a process's command line; from /proc if nil.
	PeerArgs func(pid int32) ([]string, error)

	fd       int
	Accepted atomic.Uint64
	Refused  atomic.Uint64
}

// Listen writes the trace session and listens on the socket.
func (s *SandboxSink) Listen() error {
	if s.Out == nil || s.Dir == "" || s.ActorsDir == "" {
		return errors.New("the sandbox sink needs a directory, the Actors' directory and somewhere to send points")
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return err
	}
	sock := filepath.Join(s.Dir, SandboxSocket)
	sess, err := sandboxSession(sock)
	if err != nil {
		return err
	}
	os.Remove(sock)
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: sock}); err != nil {
		unix.Close(fd)
		return fmt.Errorf("sandbox sink: bind %s: %w", sock, err)
	}
	// Only runsc, which runs as root in Substrate's Worker pods.
	if err := os.Chmod(sock, 0o600); err != nil {
		unix.Close(fd)
		return err
	}
	if err := unix.Listen(fd, 128); err != nil {
		unix.Close(fd)
		return err
	}
	// The session last: runsc reads it only once the socket accepts.
	if err := writeFileAtomic(filepath.Join(s.Dir, SandboxSessionFile), sess, 0o644); err != nil {
		unix.Close(fd)
		return err
	}
	s.fd = fd
	return nil
}

// Serve accepts sandboxes until Close.
func (s *SandboxSink) Serve() error {
	for {
		c, _, err := unix.Accept4(s.fd, unix.SOCK_CLOEXEC)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.ECONNABORTED) {
				continue
			}
			return err
		}
		uid, err := s.attribute(c)
		if err != nil {
			// The sandbox does not start: what it ran could not be
			// told apart from another Actor's.
			s.Refused.Add(1)
			log.Printf("sandbox sink: refused a sandbox: %v", err)
			unix.Close(c)
			continue
		}
		s.Accepted.Add(1)
		go s.serve(c, uid)
	}
}

// Close stops accepting; sandboxes connected keep their connections.
func (s *SandboxSink) Close() {
	unix.Shutdown(s.fd, unix.SHUT_RDWR)
	unix.Close(s.fd)
}

// attribute names the Actor of the runsc that connected, while it waits
// for the handshake.
func (s *SandboxSink) attribute(c int) (string, error) {
	cred, err := unix.GetsockoptUcred(c, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return "", err
	}
	if cred.Pid == 0 {
		return "", errors.New("the peer's process is not visible here (the sink needs the node's PID namespace)")
	}
	args, err := s.peerArgs(cred.Pid)
	if err != nil {
		return "", fmt.Errorf("pid %d: %w", cred.Pid, err)
	}
	return actorUIDFromArgs(args, s.ActorsDir)
}

func (s *SandboxSink) peerArgs(pid int32) ([]string, error) {
	if s.PeerArgs != nil {
		return s.PeerArgs(pid)
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimRight(string(b), "\x00"), "\x00"), nil
}

func (s *SandboxSink) serve(c int, uid string) {
	defer unix.Close(c)
	buf := make([]byte, 1<<20)
	// The sandbox speaks first; the answer carries the version spoken.
	n, err := unix.Read(c, buf)
	var hs pb.Handshake
	if err != nil || n == 0 || proto.Unmarshal(buf[:n], &hs) != nil {
		log.Printf("sandbox sink: Actor %s: bad handshake: %v", uid, err)
		return
	}
	reply, _ := proto.Marshal(&pb.Handshake{Version: sandboxWireVersion})
	if _, err := unix.Write(c, reply); err != nil {
		return
	}
	log.Printf("sandbox sink: Actor %s's sandbox connected (wire version %d)", uid, hs.GetVersion())
	dec := newPointDecoder(uid)
	for {
		n, err := unix.Read(c, buf)
		if err != nil || n == 0 {
			log.Printf("sandbox sink: Actor %s's sandbox closed", uid)
			return
		}
		for _, ev := range dec.decode(buf[:n]) {
			s.Out(ev)
		}
	}
}

// sandboxWireVersion is the remote sink protocol's version (gVisor's
// wire.CurrentVersion).
const sandboxWireVersion = 1

// pointDecoder turns one sandbox's points into events. It remembers its
// sockets' types, so a connect can say TCP or UDP.
type pointDecoder struct {
	uid     string
	sockets map[[2]int64]string // thread group, fd -> TCP or UDP
}

func newPointDecoder(uid string) *pointDecoder {
	return &pointDecoder{uid: uid, sockets: map[[2]int64]string{}}
}

// decode reads one message: an 8-byte header (its own size, the message
// type, points dropped since the last message), then the point.
func (p *pointDecoder) decode(msg []byte) []SandboxEvent {
	if len(msg) < 8 {
		return nil
	}
	hsize := int(binary.LittleEndian.Uint16(msg[0:2]))
	typ := pb.MessageType(binary.LittleEndian.Uint16(msg[2:4]))
	dropped := binary.LittleEndian.Uint32(msg[4:8])
	var out []SandboxEvent
	if dropped > 0 {
		out = append(out, SandboxEvent{ActorUID: p.uid, Time: time.Now().UTC(), Kind: "lost", Lost: dropped,
			Why: "the sandbox dropped them (the sink was too slow)"})
	}
	if hsize < 8 || hsize > len(msg) {
		return out
	}
	body := msg[hsize:]
	base := func(c *pb.ContextData) SandboxEvent {
		return SandboxEvent{ActorUID: p.uid, Time: time.Unix(0, c.GetTimeNs()).UTC(), PID: uint32(c.GetThreadGroupId()),
			PPID: uint32(c.GetParentThreadGroupId()), Container: c.GetContainerId(), Cwd: c.GetCwd()}
	}
	switch typ {
	case pb.MessageType_MESSAGE_SENTRY_EXEC:
		var m pb.ExecveInfo
		if proto.Unmarshal(body, &m) != nil {
			return out
		}
		ev := base(m.GetContextData())
		ev.Kind, ev.Binary, ev.Args = "exec", m.GetBinaryPath(), m.GetArgv()
		if h := m.GetBinarySha256(); len(h) > 0 {
			ev.SHA256 = hex.EncodeToString(h)
		}
		out = append(out, ev)
	case pb.MessageType_MESSAGE_SYSCALL_SOCKET:
		var m pb.Socket
		if proto.Unmarshal(body, &m) != nil || m.GetExit().GetResult() < 0 || m.GetExit().GetErrorno() != 0 {
			return out
		}
		k := [2]int64{int64(m.GetContextData().GetThreadGroupId()), m.GetExit().GetResult()}
		switch m.GetType() & 0xf {
		case unix.SOCK_STREAM:
			p.sockets[k] = "TCP"
		case unix.SOCK_DGRAM:
			p.sockets[k] = "UDP"
		default:
			delete(p.sockets, k)
		}
		if len(p.sockets) > 65536 {
			p.sockets = map[[2]int64]string{}
		}
	case pb.MessageType_MESSAGE_SYSCALL_CONNECT:
		var m pb.Connect
		if proto.Unmarshal(body, &m) != nil {
			return out
		}
		ip, port, ok := parseSockaddr(m.GetAddress())
		if !ok {
			return out // not IP: Unix sockets stay inside the sandbox
		}
		ev := base(m.GetContextData())
		ev.Kind, ev.DstIP, ev.DstPort = "connect", ip.String(), port
		ev.Proto = p.sockets[[2]int64{int64(m.GetContextData().GetThreadGroupId()), m.GetFd()}]
		if ev.Proto == "" {
			ev.Proto = "IP"
		}
		ev.Result = "ok"
		if e := m.GetExit().GetErrorno(); e != 0 {
			ev.Result = unix.ErrnoName(unix.Errno(e))
		} else if r := m.GetExit().GetResult(); r < 0 {
			ev.Result = unix.ErrnoName(unix.Errno(-r))
		}
		if ev.Result == "" {
			ev.Result = fmt.Sprintf("errno %d", m.GetExit().GetErrorno())
		}
		out = append(out, ev)
	}
	return out
}

// parseSockaddr reads an AF_INET or AF_INET6 sockaddr (Linux layout).
func parseSockaddr(b []byte) (netip.Addr, uint16, bool) {
	if len(b) < 4 {
		return netip.Addr{}, 0, false
	}
	port := binary.BigEndian.Uint16(b[2:4])
	switch binary.LittleEndian.Uint16(b[0:2]) {
	case unix.AF_INET:
		if len(b) < 8 {
			return netip.Addr{}, 0, false
		}
		return netip.AddrFrom4([4]byte(b[4:8])), port, true
	case unix.AF_INET6:
		if len(b) < 24 {
			return netip.Addr{}, 0, false
		}
		return netip.AddrFrom16([16]byte(b[8:24])).Unmap(), port, true
	}
	return netip.Addr{}, 0, false
}
