// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	pb "github.com/clovisor/clovisor/libclovisor/gvisorpoints"
)

const (
	uidA = "0f6c1f8e-2b7a-4c55-9a51-6b1f0c6a7e01"
	uidB = "9a3d2c41-7e5f-4b19-8c2d-5e4f3a2b1c02"
)

func TestActorUIDFromArgs(t *testing.T) {
	const actors = "/var/lib/ate/actors"
	for _, c := range []struct {
		args []string
		uid  string
	}{
		{[]string{"/var/lib/ate/assets/x/runsc", "-log-format", "json", "-root", actors + "/" + uidA + "/runsc-state", "create", "_sandbox"}, uidA},
		{[]string{"runsc", "--root=" + actors + "/" + uidA + "/runsc-state", "restore"}, uidA},
		{[]string{"runsc", "-root", actors + "/" + uidA + "/runsc-state/", "start"}, uidA},
		// Not runsc, or not an Actor's directory.
		{[]string{"/bin/sh", "-root", actors + "/" + uidA + "/runsc-state"}, ""},
		{[]string{"runsc", "-root", "/tmp/" + uidA + "/runsc-state"}, ""},
		{[]string{"runsc", "-root", actors + "/" + uidA + "/other"}, ""},
		{[]string{"runsc", "-root", actors + "/../actors2/" + uidA + "/runsc-state"}, ""},
		{[]string{"runsc", "-root", actors + "/not-a-uid/runsc-state"}, ""},
		{[]string{"runsc", "-root", actors + "/" + uidA + "/x/runsc-state"}, ""},
		{[]string{"runsc", "create"}, ""},
		{nil, ""},
	} {
		got, err := actorUIDFromArgs(c.args, actors)
		if got != c.uid || (c.uid == "") != (err != nil) {
			t.Errorf("%q: %q, %v; want %q", c.args, got, err, c.uid)
		}
	}
}

// msg frames a point as gVisor's remote sink does: header size, type,
// points dropped, then the point.
func msg(t *testing.T, typ pb.MessageType, dropped uint32, m proto.Message) []byte {
	t.Helper()
	body, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	h := make([]byte, 8)
	binary.LittleEndian.PutUint16(h[0:2], 8)
	binary.LittleEndian.PutUint16(h[2:4], uint16(typ))
	binary.LittleEndian.PutUint32(h[4:8], dropped)
	return append(h, body...)
}

func sockaddr4(ip string, port uint16) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint16(b[0:2], unix.AF_INET)
	binary.BigEndian.PutUint16(b[2:4], port)
	a := netip.MustParseAddr(ip).As4()
	copy(b[4:8], a[:])
	return b
}

func sockaddr6(ip string, port uint16) []byte {
	b := make([]byte, 28)
	binary.LittleEndian.PutUint16(b[0:2], unix.AF_INET6)
	binary.BigEndian.PutUint16(b[2:4], port)
	a := netip.MustParseAddr(ip).As16()
	copy(b[8:24], a[:])
	return b
}

func ctxData(tg, parent int32) *pb.ContextData {
	return &pb.ContextData{TimeNs: time.Now().UnixNano(), ThreadGroupId: tg, ParentThreadGroupId: parent,
		ContainerId: "egress", Cwd: "/work"}
}

// samplePoints: an exec, a TCP socket and its refused connect, a connect
// on an unknown socket over IPv6, a Unix connect, and a header saying
// points were dropped.
func samplePoints(t *testing.T) [][]byte {
	return [][]byte{
		msg(t, pb.MessageType_MESSAGE_SENTRY_EXEC, 0, &pb.ExecveInfo{ContextData: ctxData(7, 1), BinaryPath: "/usr/bin/curl",
			Argv: []string{"curl", "-s", "http://10.1.2.3/"}, BinarySha256: []byte{0xab, 0xcd}}),
		msg(t, pb.MessageType_MESSAGE_SYSCALL_SOCKET, 0, &pb.Socket{ContextData: ctxData(7, 1), Exit: &pb.Exit{Result: 3},
			Domain: unix.AF_INET, Type: unix.SOCK_STREAM | unix.SOCK_NONBLOCK}),
		msg(t, pb.MessageType_MESSAGE_SYSCALL_CONNECT, 0, &pb.Connect{ContextData: ctxData(7, 1), Fd: 3,
			Address: sockaddr4("10.1.2.3", 80), Exit: &pb.Exit{Result: -1, Errorno: int64(unix.ENETUNREACH)}}),
		msg(t, pb.MessageType_MESSAGE_SYSCALL_CONNECT, 0, &pb.Connect{ContextData: ctxData(8, 7), Fd: 4,
			Address: sockaddr6("2001:db8::1", 443), Exit: &pb.Exit{}}),
		msg(t, pb.MessageType_MESSAGE_SYSCALL_CONNECT, 0, &pb.Connect{ContextData: ctxData(8, 7), Fd: 5,
			Address: append([]byte{unix.AF_UNIX, 0}, "/run/x.sock"...), Exit: &pb.Exit{}}),
		msg(t, pb.MessageType_MESSAGE_SENTRY_TASK_EXIT, 3, &pb.TaskExit{ContextData: ctxData(7, 1)}),
	}
}

func checkSample(t *testing.T, evs []SandboxEvent, uid string) {
	t.Helper()
	if len(evs) != 4 {
		t.Fatalf("events: %+v", evs)
	}
	for _, e := range evs {
		if e.ActorUID != uid {
			t.Errorf("event for %q, want %q: %+v", e.ActorUID, uid, e)
		}
	}
	if e := evs[0]; e.Kind != "exec" || e.Binary != "/usr/bin/curl" || len(e.Args) != 3 || e.SHA256 != "abcd" ||
		e.PID != 7 || e.PPID != 1 || e.Cwd != "/work" || e.Container != "egress" {
		t.Errorf("exec: %+v", e)
	}
	if e := evs[1]; e.Kind != "connect" || e.Proto != "TCP" || e.DstIP != "10.1.2.3" || e.DstPort != 80 || e.Result != "ENETUNREACH" {
		t.Errorf("connect: %+v", e)
	}
	if e := evs[2]; e.Kind != "connect" || e.Proto != "IP" || e.DstIP != "2001:db8::1" || e.DstPort != 443 || e.Result != "ok" {
		t.Errorf("connect, IPv6, unknown socket: %+v", e)
	}
	if e := evs[3]; e.Kind != "lost" || e.Lost != 3 {
		t.Errorf("lost: %+v", e)
	}
}

func TestPointDecoder(t *testing.T) {
	d := newPointDecoder(uidA)
	var evs []SandboxEvent
	for _, m := range samplePoints(t) {
		evs = append(evs, d.decode(m)...)
	}
	checkSample(t, evs, uidA)
	// Short or malformed messages are skipped.
	if got := d.decode([]byte{1, 2, 3}); len(got) != 0 {
		t.Errorf("short message: %+v", got)
	}
	bad := msg(t, pb.MessageType_MESSAGE_SENTRY_EXEC, 0, &pb.ExecveInfo{})
	binary.LittleEndian.PutUint16(bad[0:2], 200)
	if got := d.decode(bad); len(got) != 0 {
		t.Errorf("header past the message: %+v", got)
	}
}

// dialSink plays a sandbox: connect, handshake, send points. It returns
// false if the sink refused it.
func dialSink(t *testing.T, sock string, points [][]byte) bool {
	t.Helper()
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Connect(fd, &unix.SockaddrUnix{Name: sock}); err != nil {
		t.Fatal(err)
	}
	hs, _ := proto.Marshal(&pb.Handshake{Version: 1})
	if _, err := unix.Write(fd, hs); err != nil {
		return false
	}
	buf := make([]byte, 64)
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5})
	n, err := unix.Read(fd, buf)
	var reply pb.Handshake
	if err != nil || n == 0 || proto.Unmarshal(buf[:n], &reply) != nil || reply.GetVersion() != 1 {
		return false
	}
	for _, p := range points {
		if _, err := unix.Write(fd, p); err != nil {
			t.Fatal(err)
		}
	}
	return true
}

func TestSandboxSink(t *testing.T) {
	// A short directory: a Unix socket's path is at most 108 bytes.
	dir, err := os.MkdirTemp("", "sink")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	actors := "/var/lib/ate/actors"
	var mu sync.Mutex
	var got []SandboxEvent
	peer := []string{"runsc", "-root", actors + "/" + uidA + "/runsc-state", "create", "_sandbox"}
	sink := &SandboxSink{Dir: dir, ActorsDir: actors,
		Out: func(e SandboxEvent) { mu.Lock(); got = append(got, e); mu.Unlock() },
		PeerArgs: func(pid int32) ([]string, error) {
			if pid != int32(os.Getpid()) {
				t.Errorf("peer pid %d, want this process's, %d", pid, os.Getpid())
			}
			mu.Lock()
			defer mu.Unlock()
			return peer, nil
		}}
	if err := sink.Listen(); err != nil {
		t.Fatal(err)
	}
	go sink.Serve()
	defer sink.Close()
	sock := filepath.Join(dir, SandboxSocket)

	// The trace session names the socket and Clovisor's points.
	var sess struct {
		TraceSession struct {
			Points []struct {
				Name string `json:"name"`
			} `json:"points"`
			Sinks []struct {
				Name   string `json:"name"`
				Config struct {
					Endpoint string `json:"endpoint"`
				} `json:"config"`
			} `json:"sinks"`
		} `json:"trace_session"`
	}
	b, err := os.ReadFile(filepath.Join(dir, SandboxSessionFile))
	if err != nil || json.Unmarshal(b, &sess) != nil {
		t.Fatalf("session: %v %s", err, b)
	}
	if s := sess.TraceSession; len(s.Sinks) != 1 || s.Sinks[0].Name != "remote" || s.Sinks[0].Config.Endpoint != sock || len(s.Points) != 3 {
		t.Errorf("session: %+v", s)
	}
	if st, err := os.Stat(sock); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("socket: %v %v", st.Mode(), err)
	}

	if !dialSink(t, sock, samplePoints(t)) {
		t.Fatal("the sink refused an Actor's sandbox")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 4 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	checkSample(t, got, uidA)
	got = nil
	// A peer that is not an Actor's runsc gets no handshake: its sandbox
	// would not start.
	peer = []string{"/bin/sh", "-c", "x"}
	mu.Unlock()
	if dialSink(t, sock, nil) {
		t.Error("the sink accepted a peer that is not an Actor's runsc")
	}
	if sink.Accepted.Load() != 1 || sink.Refused.Load() != 1 {
		t.Errorf("accepted %d, refused %d", sink.Accepted.Load(), sink.Refused.Load())
	}
}

// From sink to timeline: a forwarder posts over TLS to the receiver,
// which starts the run of an Actor it knows only by UID, and records the
// points in it.
func TestSandboxReceiver(t *testing.T) {
	dir := t.TempDir()
	reg := NewRunRegistry()
	events := make(chan AuditEvent, 256)
	api, err := NewRunAPIServer(filepath.Join(dir, "agent.sock"), nil, reg)
	if err != nil {
		t.Fatal(err)
	}
	api.Events = events
	api.SetPolicy(actorSet(t, gatewayContentProfile, gatewayCeilings))
	go api.Serve()
	defer api.Close()
	f, addr := startFakeControl(t)
	d, err := DialSubstrate(SubstrateOptions{Addr: addr, Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	api.EnableActors(d, time.Hour)
	// Five Actors, so the listing takes three pages.
	f.set(ActorInfo{ActorRef: ActorRef{"team", "r1"}, UID: uidA, Template: "researcher", State: "RUNNING"})
	for i, n := range []string{"a", "b", "c", "d"} {
		f.set(ActorInfo{ActorRef: ActorRef{"team", n}, UID: strings.Repeat(string(rune('a'+i)), 8) + "-0000-4000-8000-000000000000", State: "RUNNING"})
	}

	serving, podid := newTestCA(t, "servicedns"), newTestCA(t, "podidentity")
	srvCA, cliCA := filepath.Join(dir, "servicedns.pem"), filepath.Join(dir, "podidentity.pem")
	os.WriteFile(srvCA, serving.pem, 0o644)
	os.WriteFile(cliCA, podid.pem, 0o644)
	srv := pemPair(t, serving, dir, "server", []string{"clovisor.clovisor-system.svc"}, nil, x509.ExtKeyUsageServerAuth)
	rcv := NewSandboxReceiver(api, d, events)
	if err := rcv.Listen(GatewayTLS{Addr: netip.MustParseAddrPort("127.0.0.1:0"), CertFile: srv, ClientCA: cliCA,
		Peers: []string{SandboxSinkPeer}}); err != nil {
		t.Fatal(err)
	}
	go rcv.Serve()
	defer rcv.Close()
	url := "https://" + rcv.ln.Addr().String() + SandboxEventsPath

	forwarder := func(name, uri string) *SandboxForwarder {
		cert := pemPair(t, podid, dir, name, nil, []string{uri}, x509.ExtKeyUsageClientAuth)
		c, err := SinkClientTLS(cert, "", srvCA, "clovisor.clovisor-system.svc")
		if err != nil {
			t.Fatal(err)
		}
		return NewSandboxForwarder(url, "node-1", c)
	}
	dec := newPointDecoder(uidA)
	var sample []SandboxEvent
	for _, m := range samplePoints(t) {
		sample = append(sample, dec.decode(m)...)
	}

	// Another workload's certificate is refused.
	if err := forwarder("other", "spiffe://cluster.local/ns/team/sa/default").post(context.Background(), sample); err == nil {
		t.Error("a forwarder with another workload's certificate was admitted")
	}
	fw := forwarder("sink", SandboxSinkPeer)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fw.Run(ctx)
	for _, e := range sample {
		fw.Send(e)
	}
	// An Actor Substrate does not have.
	fw.Send(SandboxEvent{ActorUID: uidB, Time: time.Now(), Kind: "exec", Binary: "/bin/true"})
	deadline := time.Now().Add(5 * time.Second)
	for fw.Sent.Load() < uint64(len(sample)+1) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if rcv.Unattributed.Load() != 1 {
		t.Errorf("unattributed: %d, want 1", rcv.Unattributed.Load())
	}
	runID, _, ok := api.ActorRun(uidA)
	if !ok {
		t.Fatal("no run for the Actor its sandbox named")
	}
	if f.lists.Load() == 0 {
		t.Error("the Actor was found without listing")
	}
	f.remove(ActorRef{"team", "r1"})
	api.checkActors(d)

	rec, err := NewCredentialRunRecorder(filepath.Join(dir, "runs"), reg)
	if err != nil {
		t.Fatal(err)
	}
	var tl *RunTimeline
	for len(events) > 0 {
		got, err := rec.Handle(<-events)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil && got.RunID == runID {
			tl = got
		}
	}
	if tl == nil || tl.Actor == nil || tl.Actor.Name != "r1" {
		t.Fatalf("timeline: %+v", tl)
	}
	var exec, connect, gap bool
	for _, e := range tl.Events {
		switch {
		case e.Type == "exec" && e.Source == "gvisor" && e.Binary == "/usr/bin/curl" && e.SHA256 == "abcd" && e.Cwd == "/work" && e.Container == "egress":
			exec = true
		case e.Type == "connect" && e.Source == "gvisor" && e.DstIP == "10.1.2.3" && e.DstPort == 80 && e.Proto == "TCP" && e.Result == "ENETUNREACH":
			connect = true
		case e.Type == "gap" && e.Source == "gvisor" && strings.Contains(e.Note, "3 sandbox events lost"):
			gap = true
		}
	}
	if !exec || !connect || !gap {
		t.Errorf("timeline: exec %v, connect %v, gap %v: %+v", exec, connect, gap, tl.Events)
	}
	if tl.Complete || tl.Summary.Execs != 1 {
		t.Errorf("complete %v, execs %d", tl.Complete, tl.Summary.Execs)
	}
}

// Points a forwarder cannot deliver are counted per Actor, and reported
// once it can.
func TestSandboxForwarderLost(t *testing.T) {
	fw := NewSandboxForwarder("https://127.0.0.1:1"+SandboxEventsPath, "n", nil)
	fw.ch = make(chan SandboxEvent, 1)
	fw.Send(SandboxEvent{ActorUID: uidA, Kind: "exec"})
	fw.Send(SandboxEvent{ActorUID: uidA, Kind: "exec"})
	fw.Send(SandboxEvent{ActorUID: uidB, Kind: "exec"})
	if fw.lost[uidA] != 1 || fw.lost[uidB] != 1 {
		t.Errorf("lost: %v", fw.lost)
	}
}

// The trace session names only fields gVisor has: an unknown context
// field leaves a sandbox running with no points at all. These are
// `runsc trace metadata`'s, at release-20261102.0.
func TestSandboxSessionFields(t *testing.T) {
	known := map[string]bool{}
	for _, f := range strings.Split("time|thread_id|task_start_time|group_id|thread_group_start_time|container_id|credentials|cwd|process_name|parent_thread_group_id|is_exec_session", "|") {
		known[f] = true
	}
	optional := map[string][]string{
		"sentry/execve":        {"binary_info", "binary_sha256", "binary_sha1", "fd_info", "pipe_proc_info"},
		"syscall/socket/exit":  nil,
		"syscall/connect/exit": {"fd_path"},
	}
	b, err := sandboxSession("/x/gvisor.sock")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		TraceSession struct {
			Points []struct {
				Name     string   `json:"name"`
				Optional []string `json:"optional_fields"`
				Context  []string `json:"context_fields"`
			} `json:"points"`
		} `json:"trace_session"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	for _, p := range s.TraceSession.Points {
		opt, ok := optional[p.Name]
		if !ok {
			t.Errorf("point %s: not one the decoder reads", p.Name)
		}
		for _, f := range p.Context {
			if !known[f] {
				t.Errorf("point %s: no context field %q", p.Name, f)
			}
		}
		for _, f := range p.Optional {
			if !slices.Contains(opt, f) {
				t.Errorf("point %s: no optional field %q", p.Name, f)
			}
		}
	}
}
