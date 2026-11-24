// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/clovisor/clovisor/libclovisor/policy"
)

// DefaultExtProcSocket is where the node agent serves ext_proc to Envoy.
const DefaultExtProcSocket = "/run/clovisor/extproc.sock"

// HTTPData is one proxied request and the decision on it.
type HTTPData struct {
	Method    string // CONNECT for tunnels
	Host      string // hostname or IP literal
	Port      uint16
	Path      string // without query; empty for CONNECT
	Decision  string // allow, deny, tag-and-log
	Enforced  bool   // a deny that blocked (not audit-only)
	Rule      string
	Layer     string   // profile that decided a block
	WouldDeny []string // audit-mode layers that would have denied
	Reason    string   // why, when not a policy rule (guard, identity, termination)
	Message   string
	// Terminated marks a CONNECT that Envoy terminates: its requests are
	// decided, and recorded, one by one.
	Terminated bool
	// Transparent marks traffic the connect hooks redirected (milestone
	// 3.2) rather than traffic the run sent to the proxy. OrigDst is the
	// address it was sent to, SNI its TLS server name.
	Transparent bool
	OrigDst     string
	SNI         string
	// AddrMismatch: the run connected to an address the destination's
	// name does not resolve to. It was routed by name, so it reached the
	// name's address, not the one it chose.
	AddrMismatch bool
	// ResolvedName: a tunnel known only by address was decided by this
	// name, which the node's resolver had answered with the address for
	// this run (transparent mode).
	ResolvedName string
}

// ExtProcServer decides proxied requests for runs (milestone 2.3). It
// resolves the client's run from the client socket's cgroup, applies the
// run's effective policy, and answers denials with narration.
type ExtProcServer struct {
	extprocv3.UnimplementedExternalProcessorServer

	api       *RunAPIServer
	agentsDir string
	// NonRunAllowed lets clients outside any run use the proxy. Off by
	// default: the proxy exists for runs.
	NonRunAllowed bool

	events  chan<- AuditEvent
	dropped atomic.Uint64

	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	cacheMu sync.Mutex
	cache   map[string]resolved

	grpc *grpc.Server
	ln   net.Listener
	path string

	// Names, if set, returns the names the node's resolver answered with
	// an address for a run (Resolver.NamesFor).
	Names func(runCg uint64, ip netip.Addr) []string

	// Pins is the tool-definition pin store, shared with the gateway.
	Pins  *PinStore
	drift mcpDrift

	// Inspection limits (milestone 5.1); zero means the default. MaxBody
	// is the largest request body checked for content rules or MCP; a
	// larger one is refused. MaxHeldBytes bounds the bodies held at once,
	// MaxInspected and MaxInspectedPerRun the streams inspected at once.
	MaxBody            int
	MaxHeldBytes       int64
	MaxInspected       int
	MaxInspectedPerRun int
	insp               inspectLimits

	// Rates are the connection and request allowances (milestone 5.2),
	// shared with the limiter, which forgets a run's as it ends.
	Rates *RateBuckets
	// Budgets keeps model call budgets (milestone 5.4); nil: none charged.
	Budgets *BudgetLedger
}

type resolved struct {
	addrs []netip.Addr
	at    time.Time
}

// NewExtProcServer returns a server that reports decisions on events.
func NewExtProcServer(api *RunAPIServer, agentsDir string, events chan<- AuditEvent) *ExtProcServer {
	return &ExtProcServer{
		api:       api,
		agentsDir: agentsDir,
		events:    events,
		resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		cache: map[string]resolved{},
	}
}

// peerCheckListener admits only connections whose SO_PEERCRED uid is
// allowed. Anything that can talk to ext_proc can ask about any client
// 4-tuple and write events into any run's timeline, so only Envoy may.
type peerCheckListener struct {
	net.Listener
	allowed map[uint32]bool
}

func (l *peerCheckListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			continue
		}
		cred, err := peerCred(uc)
		if err == nil && l.allowed[cred.Uid] {
			return c, nil
		}
		if err == nil {
			log.Printf("ext_proc: refused connection from uid %d pid %d", cred.Uid, cred.Pid)
		}
		c.Close()
	}
}

// Listen serves on a unix socket, admitting only the given peer uids
// (root and the node agent's own uid always are).
func (s *ExtProcServer) Listen(path string, peerUIDs []uint32) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("ext_proc: listen %s: %w", path, err)
	}
	// Connect permission for everyone; the peer check decides.
	if err := os.Chmod(path, 0o666); err != nil {
		ln.Close()
		return err
	}
	// Root, and the node agent's own uid: a node agent run by a user
	// (credential identity, as on a laptop) has Envoy run as that user.
	allowed := map[uint32]bool{0: true, uint32(os.Getuid()): true}
	for _, u := range peerUIDs {
		allowed[u] = true
	}
	s.ln = &peerCheckListener{Listener: ln, allowed: allowed}
	s.path = path
	s.grpc = grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(s.grpc, s)
	return nil
}

// Serve blocks until Close.
func (s *ExtProcServer) Serve() error {
	err := s.grpc.Serve(s.ln)
	if errors.Is(err, grpc.ErrServerStopped) {
		return nil
	}
	return err
}

// Close stops serving.
func (s *ExtProcServer) Close() {
	if s.grpc != nil {
		s.grpc.Stop()
		os.Remove(s.path)
	}
}

// Process handles one HTTP stream from Envoy.
func (s *ExtProcServer) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	var st *streamState // set when this stream's body or JSON-RPC is inspected
	defer func() { st.done(s) }()
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var resp *extprocv3.ProcessingResponse
		mcp := st.remoteMCP()
		switch r := req.GetRequest().(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			st.done(s)
			resp, st = s.onHeaders(stream.Context(), req, r.RequestHeaders)
		case *extprocv3.ProcessingRequest_RequestBody:
			if st != nil && st.body != nil {
				var pre *extprocv3.ProcessingResponse
				pre, resp = s.onBody(st, r.RequestBody.GetBody(), r.RequestBody.GetEndOfStream())
				if pre != nil {
					if err := stream.Send(pre); err != nil {
						return err
					}
				}
			} else {
				resp = continueBody()
			}
		case *extprocv3.ProcessingRequest_ResponseHeaders:
			if mcp != nil {
				resp = s.onMCPResponseHeaders(mcp, r.ResponseHeaders)
			} else if b := st.budgetStream(); b != nil {
				resp = s.onBudgetResponseHeaders(b, r.ResponseHeaders)
			} else {
				resp = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseHeaders{ResponseHeaders: &extprocv3.HeadersResponse{}}}
			}
		case *extprocv3.ProcessingRequest_ResponseBody:
			if mcp != nil {
				resp = s.onMCPResponseBody(mcp, r.ResponseBody.GetBody(), r.ResponseBody.GetEndOfStream())
			} else if b := st.budgetStream(); b != nil {
				resp = s.onBudgetResponseBody(b, r.ResponseBody.GetBody(), r.ResponseBody.GetEndOfStream())
			} else {
				resp = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{ResponseBody: &extprocv3.BodyResponse{}}}
			}
		default:
			continue
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

func attribute(req *extprocv3.ProcessingRequest, name string) string {
	for _, st := range req.GetAttributes() {
		if v, ok := st.GetFields()[name]; ok {
			switch k := v.GetKind().(type) {
			case *structpb.Value_StringValue:
				return k.StringValue
			case *structpb.Value_NumberValue:
				return strconv.FormatInt(int64(k.NumberValue), 10)
			}
		}
	}
	return ""
}

func headerValue(h *corev3.HeaderMap, name string) string {
	for _, kv := range h.GetHeaders() {
		if kv.GetKey() == name {
			if kv.GetValue() != "" {
				return kv.GetValue()
			}
			return string(kv.GetRawValue())
		}
	}
	return ""
}

// attrAddrPort reads "address" (which may already include the port) and
// "port" attributes as an AddrPort.
func attrAddrPort(req *extprocv3.ProcessingRequest, addrAttr, portAttr string) (netip.AddrPort, error) {
	a := attribute(req, addrAttr)
	if ap, err := netip.ParseAddrPort(a); err == nil {
		return ap, nil
	}
	return netip.ParseAddrPort(net.JoinHostPort(a, attribute(req, portAttr)))
}

// splitAuthority parses "host:port", "[v6]:port" or a bare host.
func splitAuthority(authority string, defPort uint16) (string, uint16, error) {
	host, ps, err := net.SplitHostPort(authority)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			return strings.Trim(authority, "[]"), defPort, nil
		}
		return "", 0, err
	}
	p, err := strconv.ParseUint(ps, 10, 16)
	if err != nil || p == 0 {
		return "", 0, fmt.Errorf("bad port in %q", authority)
	}
	return host, uint16(p), nil
}

// guardClass reports addresses the proxy must never reach for a run,
// whatever the policy says: they are the node itself. Private ranges are
// left to policy, since internal services are legitimate destinations.
func guardClass(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsUnspecified() || a.IsMulticast() || a.IsInterfaceLocalMulticast()
}

const resolveCacheTTL = 30 * time.Second

// guard returns a reason to refuse a destination that is, or resolves to,
// a node-local address. A name that rebinds after this check can still
// resolve to one for Envoy; the node agent's connect gate on Envoy's
// cgroup refuses that connect in the kernel (milestone 3.5).
func (s *ExtProcServer) guard(ctx context.Context, host string, ip netip.Addr) string {
	if ip.IsValid() {
		if guardClass(ip) {
			return "destination is a node-local address"
		}
		return ""
	}
	h := policy.NormalizeHost(host)
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return "destination is a node-local name"
	}
	s.cacheMu.Lock()
	r, ok := s.cache[h]
	s.cacheMu.Unlock()
	if !ok || time.Since(r.at) > resolveCacheTTL {
		cctx, cancel := context.WithTimeout(ctx, time.Second)
		addrs, err := s.resolve(cctx, h)
		cancel()
		if err != nil {
			return "" // the dynamic forward proxy will fail the request
		}
		r = resolved{addrs: addrs, at: time.Now()}
		s.cacheMu.Lock()
		if len(s.cache) > 4096 {
			s.cache = map[string]resolved{}
		}
		s.cache[h] = r
		s.cacheMu.Unlock()
	}
	for _, a := range r.addrs {
		if guardClass(a) {
			return "destination resolves to a node-local address"
		}
	}
	return ""
}

// resolvesTo reports whether host, as the guard last resolved it, has
// address a. Unknown counts as yes: a mismatch is a note, never a denial.
func (s *ExtProcServer) resolvesTo(host string, a netip.Addr) bool {
	s.cacheMu.Lock()
	r, ok := s.cache[policy.NormalizeHost(host)]
	s.cacheMu.Unlock()
	if !ok || len(r.addrs) == 0 {
		return true
	}
	for _, x := range r.addrs {
		if x.Unmap() == a.Unmap() {
			return true
		}
	}
	return false
}

// onHeaders decides a request on its headers. The stream state it returns,
// if any, is for a request whose body or MCP traffic ext_proc inspects.
func (s *ExtProcServer) onHeaders(ctx context.Context, req *extprocv3.ProcessingRequest, h *extprocv3.HttpHeaders) (*extprocv3.ProcessingResponse, *streamState) {
	resp, o := s.decideHeaders(ctx, req, h)
	hasBody := !h.GetEndOfStream()
	if !hasBody {
		// A request with no body calls no model: nothing to charge.
		o.budgets = nil
	}
	if resp.GetImmediateResponse() != nil || (o.mcp == nil && !o.content && len(o.models) == 0 && len(o.budgets) == 0) {
		return resp, nil
	}
	hm := h.GetHeaders()
	maxBody := orDefault(s.MaxBody, DefaultMaxBody)
	d := o.d
	refuse := func(code typev3.StatusCode, reason, msg string) (*extprocv3.ProcessingResponse, *streamState) {
		cd := ContentData{Host: d.Host, Port: d.Port, Method: d.Method, Path: d.Path, Where: "body",
			Decision: policy.ActionDeny, Enforced: true, Reason: reason, Message: msg}
		s.recordContent(o.leaf, o.runCg, o.runID, cd)
		d.Decision, d.Enforced, d.Reason, d.Message = policy.ActionDeny, true, reason, msg
		return s.denyStatus(d, o.runID, code), nil
	}
	enc := ""
	if hasBody && !o.content && len(o.models) == 0 {
		// Budgets alone: an encoding that cannot be read only means the
		// model and size are unknown, and include_usage cannot be set.
		if e, ok := bodyEncoding(headerValue(hm, "content-encoding")); ok {
			enc = e
		} else {
			enc = encodingUnreadable
		}
	}
	if hasBody && (o.content || len(o.models) > 0) {
		ce := headerValue(hm, "content-encoding")
		e, ok := bodyEncoding(ce)
		if !ok {
			what := "for content rules"
			if !o.content {
				what = "for the model it names"
			}
			return refuse(typev3.StatusCode_UnsupportedMediaType, "body encoding not checkable",
				fmt.Sprintf("The request body is encoded as %q, which this proxy cannot decode to check %s, so it was not sent. "+
					"Send it uncompressed, or as gzip or deflate.", ce, what))
		}
		enc = e
	}
	// A body declared too large is refused as it arrives, at the limit,
	// not here: an HTTP/2 client still sending (curl 7.88) loses a reply
	// that comes before any of its body has gone.
	release, why := s.acquire(o.runID)
	if why != "" {
		return refuse(typev3.StatusCode_ServiceUnavailable, "inspection limit", "The request was not sent: "+why+"; retry shortly.")
	}
	st := &streamState{mcp: o.mcp, release: release}
	if hasBody {
		st.body = &heldBody{d: d, runID: o.runID, runCg: o.runCg, leaf: o.leaf, eff: o.eff, content: o.content, models: o.models, queryModel: o.queryModel, encoding: enc, max: maxBody}
	}
	if len(o.budgets) > 0 && o.mcp == nil {
		// Budgets (milestone 5.4): follow the response to read its usage.
		// Responses are asked for uncompressed, so they can be read; a
		// request that may need include_usage set loses its length.
		st.budget = &budgetStream{owners: o.budgets, d: d, runID: o.runID, leaf: o.leaf, runCg: o.runCg,
			mayInject: mayInjectUsage(d.Path), max: maxBody}
		remove := []string{"accept-encoding"}
		if st.budget.mayInject {
			remove = append(remove, "content-length")
		}
		resp.GetRequestHeaders().Response = &extprocv3.CommonResponse{HeaderMutation: &extprocv3.HeaderMutation{RemoveHeaders: remove}}
		resp.ModeOverride = budgetModes
		return resp, st
	}
	switch {
	case o.mcp != nil:
		resp.ModeOverride = mcpModes
	case hasBody:
		resp.ModeOverride = bodyModes
	default:
		// A content- or model-checked request with no body: its query
		// string was checked at headers, and there is nothing more to hold.
		st.done(s)
		return resp, nil
	}
	return resp, st
}

// headerOutcome carries what decideHeaders learned beyond the response.
type headerOutcome struct {
	mcp     *remoteMCP
	content bool // content rules cover the request: hold its body
	// models are the model lists the request must satisfy: hold its body
	// to read the model it names (milestone 5.3).
	models []policy.ModelCheck
	// queryModel: the query string named an admitted model, so a body
	// need not name one too.
	queryModel bool
	// budgets are the budgets the request is charged to (milestone 5.4).
	budgets []budgetOwner
	d       HTTPData
	runID   string
	runCg   uint64
	leaf    uint64
	eff     *policy.Effective
}

func (s *ExtProcServer) decideHeaders(ctx context.Context, req *extprocv3.ProcessingRequest, h *extprocv3.HttpHeaders) (*extprocv3.ProcessingResponse, headerOutcome) {
	hm := h.GetHeaders()
	method := headerValue(hm, ":method")
	authority := headerValue(hm, ":authority")
	path := headerValue(hm, ":path")
	rawQuery := ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path, rawQuery = path[:i], path[i+1:]
	}

	d := HTTPData{Method: method}
	phase := policy.PhaseRequest
	defPort := uint16(80)
	if method == "CONNECT" {
		phase, path = policy.PhaseConnect, ""
		defPort = 443
	}
	if headerValue(hm, hdrConnect) != "" && strings.HasPrefix(attribute(req, "source.address"), "envoy://") {
		defPort = 443 // inside a TLS tunnel, a Host without a port means 443
	}
	d.Path = path
	host, port, err := splitAuthority(authority, defPort)
	if err != nil || host == "" {
		d.Host, d.Decision, d.Reason = authority, policy.ActionDeny, "bad authority"
		d.Message = "The proxy could not parse the destination " + strconv.Quote(authority) + "."
		return s.deny(d, ""), headerOutcome{}
	}
	d.Host, d.Port = host, port
	ip, _ := netip.ParseAddr(host)

	// Identity: the cgroup of the client's socket (Phase 2 finding 1). On
	// the inner hop of a terminated connection Envoy's own source is an
	// internal address; the real client crossed the hop in x-clovisor-client,
	// which Envoy wrote, overwriting any client value. Attributes cannot be
	// set by clients, so the header is trusted only there.
	inner := strings.HasPrefix(attribute(req, "source.address"), "envoy://")
	// Plain HTTP on the transparent listener arrives from the client
	// itself, but Envoy wrote the client's socket address into a header,
	// overwriting any client value, since the local address is the
	// original destination's. Trusted on that route only.
	transparentHTTP := !inner && attribute(req, "xds.route_name") == TransparentHTTPRoute
	if inner || transparentHTTP {
		if o := headerValue(hm, hdrOrigDst); o != "" {
			d.Transparent, d.OrigDst, d.SNI = true, o, headerValue(hm, hdrSNI)
		}
	}
	runID, eff, isRun, cg, runCg := "", (*policy.Effective)(nil), false, uint64(0), uint64(0)
	var models []policy.ModelCheck
	var budgets []budgetOwner
	var src, dst netip.AddrPort
	var err1, err2 error
	if transparentHTTP {
		client, proxy, _ := strings.Cut(headerValue(hm, hdrClient), ",")
		src, err1 = netip.ParseAddrPort(client)
		dst, err2 = netip.ParseAddrPort(proxy)
	} else if inner {
		client, proxy, _ := strings.Cut(headerValue(hm, hdrClient), ",")
		src, err1 = netip.ParseAddrPort(client)
		dst, err2 = netip.ParseAddrPort(proxy)
		// Smuggling check: inside a tunnel to an allowed host, a Host
		// header naming another host would be routed there by the dynamic
		// forward proxy.
		ch, cp, cerr := splitAuthority(headerValue(hm, hdrConnect), 443)
		if cerr != nil || !strings.EqualFold(policy.NormalizeHost(ch), policy.NormalizeHost(host)) || cp != port {
			d.Decision, d.Enforced, d.Reason = policy.ActionDeny, true, "host mismatch"
			d.Message = fmt.Sprintf("The request's Host %s does not match the tunnel's destination %s.",
				net.JoinHostPort(host, strconv.Itoa(int(port))), headerValue(hm, hdrConnect))
			return s.deny(d, ""), headerOutcome{}
		}
	} else {
		src, err1 = attrAddrPort(req, "source.address", "source.port")
		dst, err2 = attrAddrPort(req, "destination.address", "destination.port")
	}
	switch {
	case s.api.CredentialIdentity():
		// The run's secret, from the proxy URL agentctl gave it: on the
		// request itself, or, inside a terminated tunnel, as Envoy carried
		// it from the CONNECT (trusted only on that hop).
		auth := headerValue(hm, "proxy-authorization")
		if inner {
			auth = headerValue(hm, hdrCred)
		}
		if user, token, ok := parseProxyBasic(auth); ok {
			runID, runCg, eff, isRun = s.api.RunForCredential(user, token)
		}
	case err1 == nil && err2 == nil:
		cg, err = SockCgroup(src, dst)
	default:
		err = fmt.Errorf("no client address")
	}
	if err == nil && !s.api.CredentialIdentity() {
		runID, runCg, eff, isRun = s.api.RunFor(cg)
		if !isRun {
			if p := findRunCgroupPath(s.agentsDir, cg); p != "" {
				// A run from before this node agent started: unprofiled.
				runID, runCg, isRun = strings.TrimPrefix(p[strings.LastIndex(p, "/")+1:], RunPrefix), cg, true
			}
		}
	}
	switch {
	case err != nil:
		d.Decision, d.Enforced, d.Reason = policy.ActionDeny, true, "unidentified client"
		d.Message = "The proxy could not identify which run this connection belongs to."
		return s.deny(d, ""), headerOutcome{}
	case !isRun && !s.NonRunAllowed:
		d.Decision, d.Enforced, d.Reason = policy.ActionDeny, true, "not a run"
		d.Message = "This proxy serves governed agent runs only; start the command with agentctl run."
		if s.api.CredentialIdentity() {
			d.Reason = "no run credential"
			d.Message = "This proxy serves governed agent runs only, known by the credential in the proxy URL " +
				"agentctl run sets; this request carried none that is valid."
			if !inner {
				// Clients such as git (libcurl with CURLAUTH_ANY) send
				// proxy credentials only when challenged.
				return proxyAuthRequired(s.deny(d, "")), headerOutcome{}
			}
		}
		return s.deny(d, ""), headerOutcome{}
	}

	reason := s.guard(ctx, host, ip)
	if d.Transparent && !ip.IsValid() && reason == "" {
		if o, err := netip.ParseAddrPort(d.OrigDst); err == nil {
			d.AddrMismatch = !s.resolvesTo(host, o.Addr())
		}
	}
	if reason != "" {
		d.Decision, d.Enforced, d.Reason = policy.ActionDeny, true, "guard: "+reason
		d.Message = "Egress to " + net.JoinHostPort(host, strconv.Itoa(int(port))) + " is refused: " + reason + "."
		s.record(cg, runCg, runID, d)
		return s.deny(d, runID), headerOutcome{}
	}

	d.Decision = policy.ActionAllow
	terminated := phase == policy.PhaseConnect && strings.HasPrefix(attribute(req, "xds.route_name"), TerminateRoutePrefix)
	// Envoy ends a terminated tunnel and sends each request inside it
	// back through here, so what the run does inside it is recorded.
	d.Terminated = terminated
	if eff != nil {
		r := policy.Request{Port: port, Method: method, Path: path, Phase: phase}
		if ip.IsValid() {
			r.IP = ip
		} else {
			r.Host = host
		}
		ed := eff.Decide(r)
		if !ed.Allowed() && ed.Rule == "" && d.Transparent && ip.IsValid() && s.Names != nil {
			// Known only by address (raw TCP, or TLS without a server
			// name), and no rule names the address: decide by the name
			// the run looked up, if the node's resolver answered it with
			// this address. An allow wins over an explicit deny.
			var deny *policy.EffectiveDecision
			for _, n := range s.Names(runCg, ip) {
				nr := r
				nr.IP, nr.Host = netip.Addr{}, n
				nd := eff.Decide(nr)
				if nd.Allowed() {
					ed, d.ResolvedName, deny = nd, n, nil
					break
				}
				if nd.Rule != "" && deny == nil {
					nd := nd
					deny, d.ResolvedName = &nd, n
				}
			}
			if deny != nil {
				ed = *deny
			}
		}
		d.Decision, d.Rule, d.Layer, d.WouldDeny, d.Enforced, d.Message = ed.Action, ed.Rule, ed.Layer, ed.WouldDeny, ed.Enforced, ed.Message
		if phase == policy.PhaseRequest && ed.Allowed() {
			models = ed.Models
		}
		switch {
		case ed.Deferred && phase == policy.PhaseConnect && ed.Allowed() && terminated:
			// Envoy terminates this tunnel; each request inside it is
			// decided on method and path.
			d.Reason = "terminated: decided per request"
		case ed.Deferred && phase == policy.PhaseConnect && ed.Allowed():
			// The deciding rule needs method or path, but Envoy will not
			// terminate this tunnel (its configuration predates the rule).
			// Passing it would leave the rule unenforced, so refuse.
			d.Decision, d.Enforced, d.Reason = policy.ActionDeny, true, "needs termination"
			d.Message = fmt.Sprintf("Rule %s needs the request's method, path or model, which this proxy cannot see "+
				"inside this TLS tunnel. An operator must restart Envoy with the current configuration.", ed.Rule)
		case phase == policy.PhaseConnect && ed.Allowed() && !terminated && !ip.IsValid() && eff.InspectsContent(host):
			// Likewise for content rules, which read what is sent inside.
			d.Decision, d.Enforced, d.Reason = policy.ActionDeny, true, "needs termination"
			d.Message = fmt.Sprintf("Content rules cover %s, but this proxy cannot read what is sent inside this TLS tunnel. "+
				"An operator must restart Envoy with the current configuration.", host)
		}
		if d.Decision != policy.ActionDeny || !d.Enforced {
			// Limits (milestone 5.2). A connection: a CONNECT, or plain
			// HTTP from the run itself. A request: anything but a CONNECT
			// Envoy terminates, whose requests come through here one by one.
			conn := phase == policy.PhaseConnect || !inner
			reqs := !(phase == policy.PhaseConnect && terminated)
			if ok, wait := s.checkRates(&d, ed, eff, runID, conn, reqs); !ok {
				s.record(cg, runCg, runID, d)
				r := s.denyStatus(d, runID, typev3.StatusCode_TooManyRequests)
				ir := r.GetImmediateResponse()
				ir.Headers.SetHeaders = append(ir.Headers.SetHeaders, &corev3.HeaderValueOption{Header: &corev3.HeaderValue{
					Key: "retry-after", RawValue: []byte(strconv.Itoa(int(retryIn(wait).Seconds())))}})
				return r, headerOutcome{}
			}
		}
		if phase == policy.PhaseRequest && ed.Allowed() && len(ed.Budgets) > 0 && (d.Decision != policy.ActionDeny || !d.Enforced) {
			// Budgets (milestone 5.4): refused once spent.
			budgets = s.budgetOwners(ed, eff, runID)
			if !s.checkBudgets(&d, budgets, runID) {
				s.record(cg, runCg, runID, d)
				return s.deny(d, runID), headerOutcome{}
			}
		}
	} else {
		d.Reason = "unprofiled run"
	}
	s.record(cg, runCg, runID, d)
	if d.Decision == policy.ActionDeny && d.Enforced {
		return s.deny(d, runID), headerOutcome{}
	}
	out := headerOutcome{d: d, runID: runID, runCg: runCg, leaf: cg, eff: eff, budgets: budgets}
	if eff != nil && phase == policy.PhaseRequest && eff.InspectsContent(host) {
		// Content rules cover this host (milestone 5.1): check the query
		// string now, and hold the body.
		if r := s.checkQuery(d, rawQuery, eff, runID, cg, runCg); r != nil {
			return r, headerOutcome{}
		}
		out.content = true
	}
	if len(models) > 0 {
		// A model rule decided (milestone 5.3): a model in the query string
		// is checked now; one in the body once it is held.
		if m, named, why := queryModel(rawQuery); named {
			if r := s.checkModel(d, models, "query string", m, why, runID, cg, runCg); r != nil {
				return r, headerOutcome{}
			}
			out.queryModel = true
		}
		out.models = models
	}
	if eff != nil && phase == policy.PhaseRequest && eff.GovernsRemoteMCP(host) {
		// A remote MCP server for this run: inspect its JSON-RPC.
		out.mcp = &remoteMCP{host: policy.NormalizeHost(host), runID: runID, runCg: runCg, eff: eff}
	}
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestHeaders{
		RequestHeaders: &extprocv3.HeadersResponse{},
	}}, out
}

// parseProxyBasic decodes a Basic Proxy-Authorization value.
func parseProxyBasic(v string) (user, pass string, ok bool) {
	scheme, cred, found := strings.Cut(strings.TrimSpace(v), " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
	if err != nil {
		return "", "", false
	}
	user, pass, ok = strings.Cut(string(raw), ":")
	if u, err := url.PathUnescape(user); err == nil {
		user = u
	}
	return user, pass, ok
}

// record files a decision under the run's own cgroup id, which is how
// the recorder keys runs, whichever child cgroup the client was in.
// record reports a decision. leaf is the client socket's cgroup (a tool
// call's, below the run, milestone 4.5), or 0 where unknown.
func (s *ExtProcServer) record(leaf, runCg uint64, runID string, d HTTPData) {
	if runID == "" || runCg == 0 || s.events == nil {
		return
	}
	if leaf == 0 {
		leaf = runCg
	}
	ev := AuditEvent{Type: EventHTTP, Timestamp: time.Now(), CgroupID: leaf, RunCgroupID: runCg, Data: d}
	select {
	case s.events <- ev:
	default:
		if n := s.dropped.Add(1); n%100 == 1 {
			log.Printf("ext_proc: event queue full; %d decisions not recorded", n)
		}
	}
}

// headerSafe makes a message usable as a header value.
func headerSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// deny answers with the narrated 403 (design §7.7). On CONNECT most
// clients drop the body, so the message is also in x-clovisor-denial.
// proxyAuthRequired turns a denial into a 407 challenge for Basic proxy
// credentials, keeping its narration.
func proxyAuthRequired(r *extprocv3.ProcessingResponse) *extprocv3.ProcessingResponse {
	ir := r.GetImmediateResponse()
	ir.Status = &typev3.HttpStatus{Code: typev3.StatusCode_ProxyAuthenticationRequired}
	ir.Headers.SetHeaders = append(ir.Headers.SetHeaders, &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{Key: "proxy-authenticate", RawValue: []byte(`Basic realm="clovisor run"`)}})
	return r
}

func (s *ExtProcServer) deny(d HTTPData, runID string) *extprocv3.ProcessingResponse {
	return s.denyStatus(d, runID, typev3.StatusCode_Forbidden)
}

// denyStatus is deny with another status: 413 for a body too large to
// check, 503 when inspection is at its limit.
func (s *ExtProcServer) denyStatus(d HTTPData, runID string, code typev3.StatusCode) *extprocv3.ProcessingResponse {
	target := net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port)))
	if d.Method != "CONNECT" {
		target = d.Host + d.Path
	}
	body, _ := json.Marshal(map[string]interface{}{
		"error":   "egress denied",
		"run":     runID,
		"profile": d.Layer,
		"rule":    d.Rule,
		"blocked": d.Method + " " + target,
		"message": d.Message,
	})
	headers := []*corev3.HeaderValueOption{
		{Header: &corev3.HeaderValue{Key: "content-type", RawValue: []byte("application/json")}},
		{Header: &corev3.HeaderValue{Key: "x-clovisor-denial", RawValue: []byte(headerSafe(d.Message))}},
	}
	if runID != "" {
		headers = append(headers, &corev3.HeaderValueOption{Header: &corev3.HeaderValue{Key: "x-clovisor-run", RawValue: []byte(runID)}})
	}
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ImmediateResponse{
		ImmediateResponse: &extprocv3.ImmediateResponse{
			Status:  &typev3.HttpStatus{Code: code},
			Body:    body,
			Headers: &extprocv3.HeaderMutation{SetHeaders: headers},
			Details: "clovisor_policy_deny",
		},
	}}
}
