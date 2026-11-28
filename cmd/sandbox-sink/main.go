// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

// Command sandbox-sink receives the gVisor Runtime Monitoring points of
// the Agent Substrate sandboxes on its node (milestone 7.5), and forwards
// them to the Clovisor that keeps the Actors' runs. It runs on every
// Worker node, as a DaemonSet, before any sandbox starts: a sandbox
// started with Clovisor's trace session does not start without it.
//
//	sandbox-sink -dir /var/lib/ate/clovisor \
//	  -forward https://clovisor.clovisor-system.svc:9444 \
//	  -cert /run/podidentity.podcert.ate.dev/credential-bundle.pem \
//	  -ca /run/servicedns.podcert.ate.dev/trust-bundle.pem
//
// With no -forward it prints each point as a JSON line.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	clovisor "github.com/clovisor/clovisor/libclovisor"
)

var (
	dir       = flag.String("dir", "/var/lib/ate/clovisor", "Directory for the socket and the trace session (runsc --pod-init-config=<dir>/session.json)")
	actorsDir = flag.String("actors-dir", "/var/lib/ate/actors", "Substrate's per-Actor directories, named by Actor UID")
	forward   = flag.String("forward", "", "The central Clovisor's sandbox listener, https://host:port; empty: print points")
	cert      = flag.String("cert", "", "The sink's client certificate (PEM), which may hold its key")
	key       = flag.String("key", "", "The key for -cert, if not in it")
	ca        = flag.String("ca", "", "The CA of the central Clovisor's certificate (PEM)")
	server    = flag.String("server-name", "", "The central Clovisor's name in its certificate (default: -forward's host)")
	node      = flag.String("node", os.Getenv("NODE_NAME"), "This node's name, sent with each batch")
)

func main() {
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	out := func(ev clovisor.SandboxEvent) { json.NewEncoder(os.Stdout).Encode(ev) }
	var fwd *clovisor.SandboxForwarder
	if *forward != "" {
		u, err := url.Parse(*forward)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			log.Fatalf("-forward must be https://host:port, not %q", *forward)
		}
		name := *server
		if name == "" {
			name = u.Hostname()
		}
		client, err := clovisor.SinkClientTLS(*cert, *key, *ca, name)
		if err != nil {
			log.Fatalf("sandbox sink: %v", err)
		}
		fwd = clovisor.NewSandboxForwarder(strings.TrimSuffix(*forward, "/")+clovisor.SandboxEventsPath, *node, client)
		go fwd.Run(ctx)
		out = fwd.Send
	}
	sink := &clovisor.SandboxSink{Dir: *dir, ActorsDir: *actorsDir, Out: out}
	if err := sink.Listen(); err != nil {
		log.Fatalf("sandbox sink: %v", err)
	}
	log.Printf("sandbox sink: on %s/%s; trace session %s/%s; forwarding to %s", *dir, clovisor.SandboxSocket, *dir, clovisor.SandboxSessionFile, *forward)
	go func() {
		<-ctx.Done()
		sink.Close()
	}()
	if fwd != nil {
		go func() {
			for range time.Tick(time.Minute) {
				log.Printf("sandbox sink: %d sandboxes accepted, %d refused; %d events forwarded", sink.Accepted.Load(), sink.Refused.Load(), fwd.Sent.Load())
			}
		}()
	}
	if err := sink.Serve(); err != nil && ctx.Err() == nil {
		log.Fatalf("sandbox sink: %v", err)
	}
}
