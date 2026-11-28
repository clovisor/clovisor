// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Sandbox audit (milestone 7.5): what an Actor's gVisor sandbox ran and
// connected to, from gVisor's Runtime Monitoring, in the Actor's
// timeline. A sink on each Worker node receives each sandbox's points,
// knows the sandbox's Actor by the runsc process that connected, and
// forwards the points to the Clovisor that keeps the Actor's run. It is
// audit only: gVisor's points cannot refuse anything.

// SandboxEvent is one point from an Actor's sandbox.
type SandboxEvent struct {
	ActorUID  string    `json:"actor_uid"`
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"` // exec, connect, lost
	PID       uint32    `json:"pid,omitempty"`
	PPID      uint32    `json:"ppid,omitempty"`
	Container string    `json:"container,omitempty"`
	Binary    string    `json:"binary,omitempty"`
	Args      []string  `json:"args,omitempty"`
	SHA256    string    `json:"sha256,omitempty"`
	Cwd       string    `json:"cwd,omitempty"`
	Proto     string    `json:"proto,omitempty"` // TCP, UDP, or IP if the socket's type is unknown
	DstIP     string    `json:"dst_ip,omitempty"`
	DstPort   uint16    `json:"dst_port,omitempty"`
	Result    string    `json:"result,omitempty"` // ok, or the errno's name
	Lost      uint32    `json:"lost,omitempty"`
	Why       string    `json:"why,omitempty"`
}

// sandboxBatch is what a sink posts: events from one node.
type sandboxBatch struct {
	Node   string         `json:"node"`
	Events []SandboxEvent `json:"events"`
}

// SandboxSocket and SandboxSessionFile are a sink's files in its Dir.
const (
	SandboxSocket      = "gvisor.sock"
	SandboxSessionFile = "session.json"
)

// SandboxEventsPath is where the central Clovisor takes sinks' batches.
const SandboxEventsPath = "/v1/sandbox-events"

// sandboxSession is the trace session each sandbox starts with
// (runsc --pod-init-config): the points Clovisor records, to the sink's
// socket.
func sandboxSession(endpoint string) ([]byte, error) {
	ctx := []string{"time", "group_id", "parent_thread_group_id", "container_id", "cwd"}
	type point struct {
		Name     string   `json:"name"`
		Optional []string `json:"optional_fields,omitempty"`
		Context  []string `json:"context_fields"`
	}
	cfg := map[string]any{"trace_session": map[string]any{
		"name": "Default",
		"points": []point{
			{Name: "sentry/execve", Optional: []string{"binary_info", "binary_sha256"}, Context: ctx},
			{Name: "syscall/socket/exit", Context: ctx},
			{Name: "syscall/connect/exit", Context: ctx},
		},
		"sinks": []map[string]any{{"name": "remote", "config": map[string]any{"endpoint": endpoint}}},
	}}
	return json.MarshalIndent(cfg, "", "  ")
}

// actorUIDRE is a Substrate Actor UID (a Kubernetes-style UUID).
var actorUIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// actorUIDFromArgs reads the Actor from the command line of the runsc
// that connected: Substrate runs each Actor's sandbox with
// -root <actorsDir>/<actor UID>/runsc-state.
func actorUIDFromArgs(args []string, actorsDir string) (string, error) {
	if len(args) == 0 || filepath.Base(args[0]) != "runsc" {
		return "", fmt.Errorf("the peer is not runsc (%q)", strings.Join(args, " "))
	}
	root := ""
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-root" || a == "--root":
			if i+1 < len(args) {
				root = args[i+1]
			}
			i++
		case strings.HasPrefix(a, "-root=") || strings.HasPrefix(a, "--root="):
			root = a[strings.IndexByte(a, '=')+1:]
		default:
			continue
		}
	}
	if root == "" {
		return "", errors.New("runsc was run with no -root")
	}
	rel, err := filepath.Rel(filepath.Clean(actorsDir), filepath.Clean(root))
	seg := strings.Split(rel, string(filepath.Separator))
	if err != nil || len(seg) != 2 || seg[1] != "runsc-state" || !actorUIDRE.MatchString(seg[0]) {
		return "", fmt.Errorf("runsc's -root %s is not %s/<actor UID>/runsc-state", root, actorsDir)
	}
	return seg[0], nil
}

// SandboxReceiver is the central Clovisor's end: it records sinks'
// events in their Actors' runs, starting a run for an Actor it has not
// seen (one that has sent no request through the gateway yet).
type SandboxReceiver struct {
	api    *RunAPIServer
	dir    ActorDirectory
	events chan<- AuditEvent
	srv    *http.Server
	ln     net.Listener

	Unattributed atomic.Uint64 // events for an Actor Substrate does not have
	Dropped      atomic.Uint64 // events the recorder had no room for
}

// NewSandboxReceiver records into api's runs, through events.
func NewSandboxReceiver(api *RunAPIServer, dir ActorDirectory, events chan<- AuditEvent) *SandboxReceiver {
	return &SandboxReceiver{api: api, dir: dir, events: events}
}

// Listen serves sinks on TLS, admitting g.Peers only.
func (r *SandboxReceiver) Listen(g GatewayTLS) error {
	ln, err := listenTLS(g, []string{"h2", "http/1.1"})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle(SandboxEventsPath, r)
	r.ln, r.srv = ln, &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return nil
}

// Serve blocks until Close.
func (r *SandboxReceiver) Serve() error {
	err := r.srv.Serve(r.ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close stops serving.
func (r *SandboxReceiver) Close() {
	if r.srv != nil {
		r.srv.Close()
	}
}

func (r *SandboxReceiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "POST a batch of sandbox events", http.StatusMethodNotAllowed)
		return
	}
	var b sandboxBatch
	if err := json.NewDecoder(io.LimitReader(req.Body, 16<<20)).Decode(&b); err != nil {
		http.Error(w, "bad batch: "+err.Error(), http.StatusBadRequest)
		return
	}
	accepted, unattributed := r.Record(req.Context(), b.Events)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"accepted": accepted, "unattributed": unattributed})
}

// Record puts events in their Actors' runs.
func (r *SandboxReceiver) Record(ctx context.Context, evs []SandboxEvent) (accepted, unattributed int) {
	runs := map[string]uint64{}
	for _, e := range evs {
		cg, ok := runs[e.ActorUID]
		if !ok {
			cg = r.runFor(ctx, e.ActorUID)
			runs[e.ActorUID] = cg
		}
		if cg == 0 {
			unattributed++
			continue
		}
		ae := AuditEvent{Timestamp: e.Time, CgroupID: cg, RunCgroupID: cg, PID: e.PID, PPID: e.PPID}
		switch e.Kind {
		case "exec":
			ae.Type = EventExec
			ae.Data = ExecData{BinaryPath: e.Binary, PID: e.PID, PPID: e.PPID, Args: e.Args, Source: "gvisor",
				SHA256: e.SHA256, Cwd: e.Cwd, Container: e.Container}
		case "connect":
			ae.Type = EventConnect
			ae.Data = ConnectData{DstIP: e.DstIP, DstPort: e.DstPort, Protocol: e.Proto, Source: "gvisor",
				Result: e.Result, Container: e.Container}
		case "lost":
			ae.Type = EventSandboxLost
			ae.Data = SandboxLostData{Count: e.Lost, Why: e.Why}
		default:
			continue
		}
		select {
		case r.events <- ae:
			accepted++
		default:
			r.Dropped.Add(1)
		}
	}
	if unattributed > 0 {
		r.Unattributed.Add(uint64(unattributed))
	}
	return accepted, unattributed
}

// runFor is the run of the Actor with uid, started if it has none; 0 if
// Substrate has no such Actor.
func (r *SandboxReceiver) runFor(ctx context.Context, uid string) uint64 {
	if _, cg, ok := r.api.ActorRun(uid); ok {
		return cg
	}
	if r.dir == nil {
		return 0
	}
	a, err := r.dir.ActorByUID(ctx, uid)
	if err != nil {
		if !errors.Is(err, ErrActorNotFound) {
			log.Printf("sandbox audit: Actor %s: %v", uid, err)
		}
		return 0
	}
	_, cg, _, err := r.api.RunForActor(a)
	if err != nil {
		log.Printf("sandbox audit: Actor %s (%s): %v", a, uid, err)
		return 0
	}
	return cg
}

// listenTLS listens on g.Addr with TLS, admitting client certificates
// from g.ClientCA naming one of g.Peers; its files are read again as they
// change.
func listenTLS(g GatewayTLS, alpn []string) (net.Listener, error) {
	if !g.Addr.IsValid() || g.CertFile == "" || g.ClientCA == "" || len(g.Peers) == 0 {
		return nil, errors.New("a TLS listener needs an address, a certificate, the CA of its clients' certificates, and their names")
	}
	if g.KeyFile == "" {
		g.KeyFile = g.CertFile
	}
	files := &gatewayFiles{g: g}
	if err := files.load(); err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: alpn,
		ClientAuth: tls.RequireAnyClientCert, // verified below, against the current CA
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c, _ := files.current()
			return c, nil
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			_, roots := files.current()
			return verifyGatewayPeer(cs.PeerCertificates, roots, g.Peers, time.Now())
		},
	}
	ln, err := net.Listen("tcp", g.Addr.String())
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", g.Addr, err)
	}
	return tls.NewListener(ln, cfg), nil
}

// SandboxForwarder sends a sink's events to the central Clovisor in
// batches. If Clovisor is unreachable it keeps up to its buffer and then
// counts what it loses, per Actor, and reports those counts once it can:
// sandboxes keep running, as gVisor's own sink does once started.
type SandboxForwarder struct {
	URL    string
	Node   string
	Client *http.Client

	ch   chan SandboxEvent
	mu   sync.Mutex
	lost map[string]uint32
	// Sent counts events Clovisor accepted.
	Sent atomic.Uint64
}

// NewSandboxForwarder posts to url with client.
func NewSandboxForwarder(url, node string, client *http.Client) *SandboxForwarder {
	return &SandboxForwarder{URL: url, Node: node, Client: client, ch: make(chan SandboxEvent, 16384), lost: map[string]uint32{}}
}

// Send queues ev; it never blocks a sandbox's connection.
func (f *SandboxForwarder) Send(ev SandboxEvent) {
	select {
	case f.ch <- ev:
	default:
		f.mu.Lock()
		f.lost[ev.ActorUID]++
		f.mu.Unlock()
	}
}

// Run sends batches until ctx ends.
func (f *SandboxForwarder) Run(ctx context.Context) {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	var batch []SandboxEvent
	flush := func() {
		f.mu.Lock()
		for uid, n := range f.lost {
			batch = append(batch, SandboxEvent{ActorUID: uid, Time: time.Now().UTC(), Kind: "lost", Lost: n,
				Why: "the node's sink could not forward them"})
		}
		f.lost = map[string]uint32{}
		f.mu.Unlock()
		if len(batch) == 0 {
			return
		}
		var err error
		for try, wait := 0, 200*time.Millisecond; try < 4; try, wait = try+1, wait*2 {
			if err = f.post(ctx, batch); err == nil {
				f.Sent.Add(uint64(len(batch)))
				break
			}
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return
			}
		}
		if err != nil {
			log.Printf("sandbox sink: %d events not forwarded: %v", len(batch), err)
			f.mu.Lock()
			for _, e := range batch {
				if e.Kind == "lost" {
					f.lost[e.ActorUID] += e.Lost
				} else {
					f.lost[e.ActorUID]++
				}
			}
			f.mu.Unlock()
		}
		batch = nil
	}
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-f.ch:
			batch = append(batch, e)
			if len(batch) >= 512 {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

func (f *SandboxForwarder) post(ctx context.Context, evs []SandboxEvent) error {
	body, err := json.Marshal(sandboxBatch{Node: f.Node, Events: evs})
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, f.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", f.URL, resp.Status)
	}
	return nil
}

// SinkClientTLS is the sink's client side: its certificate, and the CA and
// name of the central Clovisor's, read again as they change.
func SinkClientTLS(certFile, keyFile, caFile, serverName string) (*http.Client, error) {
	if keyFile == "" {
		keyFile = certFile
	}
	f := &gatewayFiles{g: GatewayTLS{CertFile: certFile, KeyFile: keyFile, ClientCA: caFile}}
	if err := f.load(); err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			c, _ := f.current()
			return c, nil
		},
		// Verified against the current CA below, rather than a fixed pool.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			_, roots := f.current()
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: serverName})
			return err
		},
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}}, nil
}
