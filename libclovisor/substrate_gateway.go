// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"sync"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
)

// Beside Substrate's egress gateway (milestone 7.4), Clovisor is the
// additional ext_proc Substrate's Envoy calls on each request it can read
// (cleartext HTTP, and TLS it terminates), after Substrate has verified
// the Actor's certificate and allowed the request by its EgressPolicy.
// Clovisor's Envoy is not involved: the Actor is known by what Substrate's
// Envoy asserts in request attributes, which nothing the Actor sends can
// set, over a connection only that Envoy can make.
const (
	// SubstrateActorAttr is the Actor's SPIFFE ID, which Substrate's Envoy
	// read from the Actor's verified certificate on the CONNECT.
	SubstrateActorAttr = "filter_state['dev.ate.actor.identity']"
	// SubstrateDialedAttr is the IP:port the Actor dialed. A port in the
	// request's Host was never checked; the gateway dials this one.
	SubstrateDialedAttr = "filter_state['dev.ate.connect.authority']"
	// SubstrateSNIAttr is the TLS server name of a terminated tunnel.
	SubstrateSNIAttr = "connection.requested_server_name"
	// SubstratePeer is the SPIFFE ID of Substrate's egress gateway pods,
	// from the podidentity signer.
	SubstratePeer = "spiffe://cluster.local/ns/ate-system/sa/atenet-egress"
	// SandboxSinkPeer is the SPIFFE ID of Clovisor's sandbox sinks
	// (milestone 7.5), the clovisor-sandbox ServiceAccount's.
	SandboxSinkPeer = "spiffe://cluster.local/ns/clovisor-system/sa/clovisor-sandbox"
	// SubstrateGatewayAPITimeout bounds a call to Substrate's API while
	// the gateway waits, 2s, for Clovisor's answer: Clovisor answers that
	// the directory is unavailable rather than letting the gateway time out.
	SubstrateGatewayAPITimeout = 1500 * time.Millisecond
)

// SubstrateGateway configures ext_proc for Substrate's gateway.
type SubstrateGateway struct {
	// TrustDomain of the Actors' SPIFFE IDs; DefaultActorTrustDomain if "".
	TrustDomain string
}

// GatewayTLS is the listener Substrate's Envoy calls: TLS with a client
// certificate, from Peers only. The files are read again as they change
// (pod certificates rotate), and a key may share its certificate's file.
type GatewayTLS struct {
	Addr     netip.AddrPort
	CertFile string // this server's certificate (servicedns, for <svc>.<ns>.svc)
	KeyFile  string
	ClientCA string   // verifies the gateway's client certificate (podidentity)
	Peers    []string // URI SANs admitted; SubstratePeer if empty
}

// substrateActor reads the Actor from the identity Substrate's Envoy
// asserted. Envoy sets it from the certificate it verified against the
// Actor CA, and Substrate's ext_proc has accepted it before Clovisor is
// asked.
func substrateActor(id, trustDomain string) (ActorRef, error) {
	if id == "" {
		return ActorRef{}, errors.New("Substrate's gateway sent no Actor identity")
	}
	if trustDomain == "" {
		trustDomain = DefaultActorTrustDomain
	}
	u, err := url.Parse(id)
	if err != nil {
		return ActorRef{}, fmt.Errorf("Substrate's gateway sent Actor identity %q: %w", id, err)
	}
	return actorFromSPIFFE(u, trustDomain)
}

// ListenGateway serves ext_proc on TCP for Substrate's Envoy.
func (s *ExtProcServer) ListenGateway(g GatewayTLS) error {
	if len(g.Peers) == 0 {
		g.Peers = []string{SubstratePeer}
	}
	// TLS under gRPC rather than gRPC's TLS credentials, which refuse a
	// client that negotiates no ALPN, as Substrate's Envoy cluster does.
	// Handlers need nothing from the connection: who may call is decided
	// in the handshake.
	ln, err := listenTLS(g, []string{"h2"})
	if err != nil {
		return fmt.Errorf("ext_proc for Substrate: %w", err)
	}
	s.ln = ln
	s.grpc = grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(s.grpc, s)
	return nil
}

// verifyGatewayPeer admits a client certificate from roots, for client
// authentication, naming one of peers.
func verifyGatewayPeer(chain []*x509.Certificate, roots *x509.CertPool, peers []string, now time.Time) error {
	if len(chain) == 0 {
		return errors.New("no client certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("client certificate: %w", err)
	}
	for _, u := range chain[0].URIs {
		if slices.Contains(peers, u.String()) {
			return nil
		}
	}
	names := []string{}
	for _, u := range chain[0].URIs {
		names = append(names, u.String())
	}
	log.Printf("ext_proc: refused a client certificate for %v: not one of %v", names, peers)
	return fmt.Errorf("client certificate names %v, not Substrate's gateway", names)
}

// gatewayFiles holds the listener's certificate and client CA, read again
// when their files change.
type gatewayFiles struct {
	g GatewayTLS

	mu      sync.Mutex
	cert    *tls.Certificate
	roots   *x509.CertPool
	stamp   [3]time.Time
	checked time.Time
}

func (f *gatewayFiles) load() error {
	var stamp [3]time.Time
	for i, p := range []string{f.g.CertFile, f.g.KeyFile, f.g.ClientCA} {
		st, err := os.Stat(p)
		if err != nil {
			return err
		}
		stamp[i] = st.ModTime()
	}
	if f.cert != nil && stamp == f.stamp {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(f.g.CertFile, f.g.KeyFile)
	if err != nil {
		return fmt.Errorf("ext_proc certificate: %w", err)
	}
	pem, err := os.ReadFile(f.g.ClientCA)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("%s holds no certificates", f.g.ClientCA)
	}
	f.cert, f.roots, f.stamp = &cert, roots, stamp
	return nil
}

// current returns the files as last read, checking them at most every
// few seconds. A file that fails to read keeps the last good one.
func (f *gatewayFiles) current() (*tls.Certificate, *x509.CertPool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if time.Since(f.checked) > 5*time.Second {
		f.checked = time.Now()
		if err := f.load(); err != nil {
			log.Printf("ext_proc: reloading %s: %v; keeping the last", f.g.CertFile, err)
		}
	}
	return f.cert, f.roots
}
