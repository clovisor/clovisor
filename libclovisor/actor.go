// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

// Actor identity (milestone 7.3): runs are Agent Substrate Actors. An
// Actor reaches the proxy over mTLS with its certificate, whose SPIFFE ID
// names it (spiffe://<trust domain>/worker-for-actor/<atespace>/<actor>).
// Envoy verifies the certificate at the handshake and forwards the chain
// in x-forwarded-client-cert; ext_proc verifies it again, as Substrate's
// own gateway does, and asks Substrate's Control API whether the Actor
// exists and is placed on a Worker. The run is the Actor's UID, so its
// timeline spans suspend, resume and moves between Workers.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/clovisor/clovisor/libclovisor/substrateapi"
)

// DefaultActorTrustDomain is the SPIFFE trust domain of Substrate's Actor
// certificates.
const DefaultActorTrustDomain = "substrate-actor.local"

// ActorRef names an Actor.
type ActorRef struct {
	Atespace string `json:"atespace"`
	Name     string `json:"name"`
}

func (r ActorRef) String() string { return r.Atespace + "/" + r.Name }

// ActorInfo is what Substrate says of an Actor.
type ActorInfo struct {
	ActorRef
	UID      string `json:"uid"`
	Template string `json:"template,omitempty"` // its ActorTemplate, in the same atespace
	State    string `json:"state,omitempty"`
}

// Placed reports whether the Actor is on a Worker, the only states in
// which Substrate lets it reach the network: RESUMING is saved with the
// Worker assignment, so a booting Actor can.
func (a ActorInfo) Placed() bool { return a.State == "RUNNING" || a.State == "RESUMING" }

// InnerActorMaxAge is how old an answer about an Actor may be for a
// request inside a tunnel, whose CONNECT asked Substrate itself. A CONNECT
// or a plain request always asks, as Substrate's own gateway does, so a
// suspended or deleted Actor gets no new tunnel from a stale answer.
const InnerActorMaxAge = 2 * time.Second

// ErrActorNotFound is returned for an Actor Substrate does not have.
var ErrActorNotFound = errors.New("no such Actor")

// ActorDirectory answers what Substrate knows of an Actor, from an answer
// no older than maxAge (0: ask now).
type ActorDirectory interface {
	Actor(ctx context.Context, ref ActorRef, maxAge time.Duration) (ActorInfo, error)
}

// SubstrateOptions reach Substrate's Control API.
type SubstrateOptions struct {
	Addr       string // host:port
	CAFile     string // verifies the API server; required unless Insecure
	ServerName string // the API server's name in its certificate, if not Addr's host
	CertFile   string // Clovisor's client certificate, if the API asks for one
	KeyFile    string
	Insecure   bool // plaintext, for tests only

}

// substrateDirectory asks Substrate's Control API, caching answers briefly.
type substrateDirectory struct {
	client substrateapi.ControlClient
	mu     sync.Mutex
	cache  map[ActorRef]cachedActor
}

type cachedActor struct {
	info ActorInfo
	err  error
	at   time.Time
}

// DialSubstrate connects to Substrate's Control API.
func DialSubstrate(o SubstrateOptions) (ActorDirectory, error) {
	if o.Addr == "" {
		return nil, fmt.Errorf("the Actor directory needs Substrate's API address")
	}
	var creds credentials.TransportCredentials
	if o.Insecure {
		creds = insecure.NewCredentials()
	} else {
		if o.CAFile == "" {
			return nil, fmt.Errorf("Substrate's API needs a CA to verify it (or plaintext, for tests)")
		}
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no certificates", o.CAFile)
		}
		cfg := &tls.Config{RootCAs: roots, ServerName: o.ServerName, MinVersion: tls.VersionTLS12}
		if o.CertFile != "" {
			cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
			if err != nil {
				return nil, err
			}
			cfg.Certificates = []tls.Certificate{cert}
		}
		creds = credentials.NewTLS(cfg)
	}
	conn, err := grpc.NewClient(o.Addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	return &substrateDirectory{client: substrateapi.NewControlClient(conn), cache: map[ActorRef]cachedActor{}}, nil
}

func (d *substrateDirectory) Actor(ctx context.Context, ref ActorRef, maxAge time.Duration) (ActorInfo, error) {
	d.mu.Lock()
	if c, ok := d.cache[ref]; ok && time.Since(c.at) < maxAge {
		d.mu.Unlock()
		return c.info, c.err
	}
	d.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	a, err := d.client.GetActor(ctx, &substrateapi.GetActorRequest{Actor: &substrateapi.ObjectRef{Atespace: ref.Atespace, Name: ref.Name}})
	var info ActorInfo
	switch {
	case grpcstatus.Code(err) == codes.NotFound:
		err = ErrActorNotFound
	case err != nil:
		return ActorInfo{}, fmt.Errorf("Substrate's API: %w", err) // not cached: the API failed, not the Actor
	default:
		info = ActorInfo{ActorRef: ref, UID: a.GetMetadata().GetUid(), Template: a.GetActorTemplate().GetName(),
			State: strings.TrimPrefix(a.GetStatus().GetState().String(), "ACTOR_STATE_")}
		if info.UID == "" {
			return ActorInfo{}, fmt.Errorf("Substrate's API returned Actor %s with no UID", ref)
		}
	}
	d.mu.Lock()
	d.cache[ref] = cachedActor{info: info, err: err, at: time.Now()}
	if len(d.cache) > 10000 {
		for k, c := range d.cache {
			if time.Since(c.at) >= InnerActorMaxAge {
				delete(d.cache, k)
			}
		}
	}
	d.mu.Unlock()
	return info, err
}

// ActorVerifier turns the certificate chain Envoy forwarded into the
// Actor it certifies.
type ActorVerifier struct {
	Roots       *x509.CertPool
	TrustDomain string
	Now         func() time.Time // time.Now if nil

	mu    sync.Mutex
	cache map[[32]byte]verified
}

type verified struct {
	ref      ActorRef
	notAfter time.Time
}

// NewActorVerifier verifies Actor certificates against the CA certificates
// in caFile.
func NewActorVerifier(caFile, trustDomain string) (*ActorVerifier, error) {
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("%s holds no certificates", caFile)
	}
	if trustDomain == "" {
		trustDomain = DefaultActorTrustDomain
	}
	return &ActorVerifier{Roots: roots, TrustDomain: trustDomain}, nil
}

// Verify checks the chain in an x-forwarded-client-cert value: a client
// certificate signed by the Actor CA, not a CA itself, for client
// authentication, within its validity, with one SPIFFE ID naming an
// Actor. A chain once verified is remembered until its certificate
// expires, so the requests inside a tunnel cost no signature check each.
func (v *ActorVerifier) Verify(xfcc string) (ActorRef, error) {
	if xfcc == "" || xfcc == "-" {
		return ActorRef{}, fmt.Errorf("the connection presented no client certificate")
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	key := sha256.Sum256([]byte(xfcc))
	v.mu.Lock()
	if c, ok := v.cache[key]; ok && now.Before(c.notAfter) {
		v.mu.Unlock()
		return c.ref, nil
	}
	v.mu.Unlock()

	chain, err := parseXFCCChain(xfcc)
	if err != nil {
		return ActorRef{}, err
	}
	leaf := chain[0]
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return ActorRef{}, fmt.Errorf("the Actor certificate is outside its validity (%s to %s)",
			leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
	}
	if leaf.IsCA {
		return ActorRef{}, fmt.Errorf("the Actor certificate is a CA certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: v.Roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return ActorRef{}, fmt.Errorf("the Actor certificate is not from the Actor CA: %w", err)
	}
	if len(leaf.URIs) != 1 {
		return ActorRef{}, fmt.Errorf("the Actor certificate has %d URI names, want 1", len(leaf.URIs))
	}
	ref, err := actorFromSPIFFE(leaf.URIs[0], v.TrustDomain)
	if err != nil {
		return ActorRef{}, err
	}
	v.mu.Lock()
	if v.cache == nil || len(v.cache) > 10000 {
		v.cache = map[[32]byte]verified{}
	}
	v.cache[key] = verified{ref: ref, notAfter: leaf.NotAfter}
	v.mu.Unlock()
	return ref, nil
}

// resourceNameRE is Substrate's resource name: a DNS label.
var resourceNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// actorFromSPIFFE reads spiffe://<trust domain>/worker-for-actor/<atespace>/<actor>.
func actorFromSPIFFE(u *url.URL, trustDomain string) (ActorRef, error) {
	bad := fmt.Errorf("%q is not spiffe://%s/worker-for-actor/<atespace>/<actor>", u.String(), trustDomain)
	if u.Scheme != "spiffe" || u.Host != trustDomain || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ActorRef{}, bad
	}
	seg := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(seg) != 3 || seg[0] != "worker-for-actor" || !resourceNameRE.MatchString(seg[1]) || !resourceNameRE.MatchString(seg[2]) {
		return ActorRef{}, bad
	}
	return ActorRef{Atespace: seg[1], Name: seg[2]}, nil
}

// parseXFCCChain reads the presented chain, leaf first, from an
// x-forwarded-client-cert value. Envoy, set to sanitize and set it, is its
// only writer, so it holds one element: this connection's.
func parseXFCCChain(xfcc string) ([]*x509.Certificate, error) {
	elems := splitXFCC(xfcc, ',')
	if len(elems) != 1 {
		return nil, fmt.Errorf("x-forwarded-client-cert has %d elements, want 1", len(elems))
	}
	var chainPEM, certPEM string
	for _, kv := range splitXFCC(elems[0], ';') {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		v = strings.TrimSuffix(strings.TrimPrefix(v, `"`), `"`)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "chain":
			chainPEM = v
		case "cert":
			certPEM = v
		}
	}
	enc := chainPEM
	if enc == "" {
		enc = certPEM
	}
	if enc == "" {
		return nil, fmt.Errorf("x-forwarded-client-cert carries no certificate")
	}
	// Envoy percent-encodes the PEM. PathUnescape, not QueryUnescape,
	// which would turn base64's '+' into spaces.
	raw, err := url.PathUnescape(enc)
	if err != nil {
		return nil, fmt.Errorf("x-forwarded-client-cert: %w", err)
	}
	var chain []*x509.Certificate
	rest := []byte(raw)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x-forwarded-client-cert: %w", err)
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("x-forwarded-client-cert carries no certificate")
	}
	return chain, nil
}

// splitXFCC splits on sep outside double quotes.
func splitXFCC(s string, sep byte) []string {
	var out []string
	quoted, start := false, 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && quoted:
			i++
		case s[i] == '"':
			quoted = !quoted
		case s[i] == sep && !quoted:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}
