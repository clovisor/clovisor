// Command extproc is the Phase 2 milestone 2.0 ext_proc spike: it resolves
// the client's run cgroup from the downstream source address, applies a
// host deny list, and answers denials with a narrated 403.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/clovisor/clovisor/spikes/phase2/sockdiag"
	"golang.org/x/sys/unix"
)

var (
	listen   = flag.String("listen", "127.0.0.1:9001", "gRPC listen address")
	deny     = flag.String("deny", "", "comma-separated hosts to deny")
	agents   = flag.String("agents", "/sys/fs/cgroup/agents", "agents cgroup dir")
	denyPath = flag.String("deny-path", "", "deny requests whose path has this prefix (inner, terminated hop only)")
)

type server struct {
	extproc.UnimplementedExternalProcessorServer
	deny map[string]bool
}

func attr(req *extproc.ProcessingRequest, name string) string {
	for _, s := range req.GetAttributes() {
		if v, ok := s.GetFields()[name]; ok {
			switch k := v.GetKind().(type) {
			case *structpb.Value_StringValue:
				return k.StringValue
			case *structpb.Value_NumberValue:
				return fmt.Sprint(int64(k.NumberValue))
			}
		}
	}
	return ""
}

func header(h *corev3.HeaderMap, name string) string {
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

// runOf maps a cgroup id to the run under agents/, by directory inode.
func runOf(id uint64) string {
	var found string
	filepath.WalkDir(*agents, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() || found != "" {
			return nil
		}
		var st unix.Stat_t
		if unix.Stat(p, &st) == nil && st.Ino == id {
			rel, _ := filepath.Rel(*agents, p)
			found = strings.SplitN(rel, "/", 2)[0]
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func addrPort(addr, port string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap, nil
	}
	return netip.ParseAddrPort(net.JoinHostPort(addr, port))
}

func (s *server) Process(stream extproc.ExternalProcessor_ProcessServer) error {
	var run string
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var resp *extproc.ProcessingResponse
		switch r := req.GetRequest().(type) {
		case *extproc.ProcessingRequest_RequestHeaders:
			start := time.Now()
			h := r.RequestHeaders.GetHeaders()
			method, authority, path := header(h, ":method"), header(h, ":authority"), header(h, ":path")
			src := attr(req, "source.address")
			dst := attr(req, "destination.address")
			client := header(h, "x-clovisor-client") // set by Envoy on the inner (terminated) hop

			lookupSrc, lookupDst := src, dst
			if client != "" {
				parts := strings.SplitN(client, ",", 2)
				if len(parts) == 2 {
					lookupSrc, lookupDst = parts[0], parts[1]
				}
			}
			cg := uint64(0)
			var cerr error
			if ls, err1 := addrPort(lookupSrc, attr(req, "source.port")); err1 == nil {
				if ld, err2 := addrPort(lookupDst, attr(req, "destination.port")); err2 == nil {
					cg, cerr = sockdiag.CgroupOf(ls, ld)
				}
			}
			if cg != 0 {
				run = runOf(cg)
			}
			host := authority
			if hh, _, err := net.SplitHostPort(authority); err == nil {
				host = hh
			}
			decision := "allow"
			if s.deny[host] || (*denyPath != "" && method != "CONNECT" && strings.HasPrefix(path, *denyPath)) {
				decision = "deny"
			}
			log.Printf("%s %s %s src=%s dst=%s client=%q cgroup=%d (%v) run=%q decision=%s lookup+decide=%v",
				method, authority, path, src, dst, client, cg, cerr, run, decision, time.Since(start))

			if decision == "deny" {
				body, _ := json.Marshal(map[string]string{
					"policy":  "spike",
					"blocked": method + " " + authority,
					"message": "Egress to " + host + path + " is not allowed for this run.",
					"run":     run,
				})
				resp = &extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_ImmediateResponse{
					ImmediateResponse: &extproc.ImmediateResponse{
						Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
						Body:   body,
						Headers: &extproc.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{
							{Header: &corev3.HeaderValue{Key: "content-type", RawValue: []byte("application/json")}},
							{Header: &corev3.HeaderValue{Key: "x-clovisor-denial", RawValue: []byte("Egress to " + host + " is not allowed for this run.")}},
						}},
						Details: "clovisor_policy_deny",
					},
				}}
			} else {
				resp = &extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_RequestHeaders{
					RequestHeaders: &extproc.HeadersResponse{},
				}}
			}
		case *extproc.ProcessingRequest_RequestBody:
			b := r.RequestBody
			log.Printf("  body: %d bytes end_of_stream=%v run=%q: %.80q", len(b.GetBody()), b.GetEndOfStream(), run, b.GetBody())
			resp = &extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_RequestBody{
				RequestBody: &extproc.BodyResponse{},
			}}
		case *extproc.ProcessingRequest_ResponseHeaders:
			resp = &extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_ResponseHeaders{
				ResponseHeaders: &extproc.HeadersResponse{},
			}}
		case *extproc.ProcessingRequest_ResponseBody:
			resp = &extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_ResponseBody{
				ResponseBody: &extproc.BodyResponse{},
			}}
		default:
			continue
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

func main() {
	flag.Parse()
	s := &server{deny: map[string]bool{}}
	for _, h := range strings.Split(*deny, ",") {
		if h != "" {
			s.deny[h] = true
		}
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	g := grpc.NewServer()
	extproc.RegisterExternalProcessorServer(g, s)
	log.Printf("ext_proc spike listening on %s, deny=%v", *listen, *deny)
	log.Fatal(g.Serve(ln))
}
