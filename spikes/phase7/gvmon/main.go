// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

// Command gvmon is the Phase 7.0 spike's receiver for gVisor Runtime
// Monitoring: the remote sink's server end. Each sandbox connects to the
// Unix socket (SOCK_SEQPACKET) and sends a Handshake, answered with ours;
// then each message is a wire.Header and a protobuf, printed here as one
// JSON line, with the point's type and how late it arrived.
//
//	gvmon -listen /tmp/gvisor_events.sock
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/wire"

	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

var listen = flag.String("listen", "/tmp/gvisor_events.sock", "Unix socket the sandboxes' remote sink connects to")

// message is the protobuf for each point type the spike enables.
func message(t pb.MessageType) proto.Message {
	switch t {
	case pb.MessageType_MESSAGE_CONTAINER_START:
		return &pb.Start{}
	case pb.MessageType_MESSAGE_SENTRY_CLONE:
		return &pb.CloneInfo{}
	case pb.MessageType_MESSAGE_SENTRY_EXEC:
		return &pb.ExecveInfo{}
	case pb.MessageType_MESSAGE_SENTRY_TASK_EXIT:
		return &pb.TaskExit{}
	case pb.MessageType_MESSAGE_SYSCALL_CONNECT:
		return &pb.Connect{}
	case pb.MessageType_MESSAGE_SYSCALL_EXECVE:
		return &pb.Execve{}
	case pb.MessageType_MESSAGE_SYSCALL_SOCKET:
		return &pb.Socket{}
	}
	return nil
}

func main() {
	flag.Parse()
	os.Remove(*listen)
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		log.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: *listen}); err != nil {
		log.Fatal(err)
	}
	os.Chmod(*listen, 0o666)
	if err := unix.Listen(fd, 16); err != nil {
		log.Fatal(err)
	}
	log.Printf("gvmon on %s", *listen)
	for n := 0; ; n++ {
		c, _, err := unix.Accept(fd)
		if err != nil {
			log.Fatal(err)
		}
		go serve(n, c)
	}
}

func serve(conn, fd int) {
	defer unix.Close(fd)
	buf := make([]byte, 1<<20)
	// The sandbox speaks first.
	n, err := unix.Read(fd, buf)
	if err != nil {
		log.Printf("conn %d: handshake: %v", conn, err)
		return
	}
	var hs pb.Handshake
	if err := proto.Unmarshal(buf[:n], &hs); err != nil {
		log.Printf("conn %d: handshake: %v", conn, err)
		return
	}
	out, _ := proto.Marshal(&pb.Handshake{Version: wire.CurrentVersion})
	if _, err := unix.Write(fd, out); err != nil {
		log.Printf("conn %d: handshake reply: %v", conn, err)
		return
	}
	log.Printf("conn %d: sandbox connected (version %d)", conn, hs.Version)
	enc := json.NewEncoder(os.Stdout)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil || n == 0 {
			log.Printf("conn %d: closed: %v", conn, err)
			return
		}
		if n < wire.HeaderStructSize {
			continue
		}
		size := binary.LittleEndian.Uint16(buf[0:2])
		typ := pb.MessageType(binary.LittleEndian.Uint16(buf[2:4]))
		dropped := binary.LittleEndian.Uint32(buf[4:8])
		m := message(typ)
		line := map[string]any{"conn": conn, "type": typ.String()}
		if dropped > 0 {
			line["dropped"] = dropped
		}
		if m != nil && int(size) <= n {
			if err := proto.Unmarshal(buf[size:n], m); err == nil {
				var v map[string]any
				js, _ := protojson.Marshal(m)
				json.Unmarshal(js, &v)
				line["event"] = v
				if ctx, ok := v["contextData"].(map[string]any); ok {
					if t, ok := ctx["timeNs"].(string); ok {
						var ns int64
						fmt.Sscan(t, &ns)
						line["lag_us"] = time.Since(time.Unix(0, ns)).Microseconds()
					}
				}
			}
		}
		enc.Encode(line)
	}
}
