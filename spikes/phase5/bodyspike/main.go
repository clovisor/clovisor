// Command bodyspike is the Phase 5 milestone 5.0 spike for Envoy body
// handling and held ext_proc streams. Subcommands:
//
//	extproc   an ext_proc server whose behaviour each request picks with
//	          the x-spike header (see modes below)
//	upstream  an HTTP server that echoes bodies and streams SSE in the
//	          shapes of the Anthropic and OpenAI APIs
//	bench     latency of requests through Envoy for a mode and body size
//	hold      holds N requests in ext_proc, then times a normal request
//
// Modes (x-spike): none, buf, redact, inject, sse, hold:<seconds>,
// holdnoover:<seconds>, partial.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: bodyspike extproc|upstream|bench|hold [flags]")
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "extproc":
		runExtproc(args)
	case "upstream":
		runUpstream(args)
	case "bench":
		runBench(args)
	case "hold":
		runHold(args)
	default:
		log.Fatalf("unknown %s", cmd)
	}
}

// ---- ext_proc ----

type srv struct {
	extproc.UnimplementedExternalProcessorServer
	held, streams, bodies, chunks atomic.Int64
	maxChunk                      atomic.Int64
}

func hdr(h *corev3.HeaderMap, k string) string {
	for _, kv := range h.GetHeaders() {
		if kv.GetKey() == k {
			if kv.GetValue() != "" {
				return kv.GetValue()
			}
			return string(kv.GetRawValue())
		}
	}
	return ""
}

func cont() *extproc.CommonResponse { return &extproc.CommonResponse{} }

var secret = regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`)

func (s *srv) Process(st extproc.ExternalProcessor_ProcessServer) error {
	s.streams.Add(1)
	var mode string
	var sse sseUsage
	var seen int
	var acc []byte
	for {
		req, err := st.Recv()
		if err != nil {
			if mode == "sse" {
				log.Printf("sse stream ended: %s", sse.summary())
			}
			return nil
		}
		var resp *extproc.ProcessingResponse
		switch r := req.GetRequest().(type) {
		case *extproc.ProcessingRequest_RequestHeaders:
			mode = hdr(r.RequestHeaders.GetHeaders(), "x-spike")
			resp = &extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_RequestHeaders{
				RequestHeaders: &extproc.HeadersResponse{Response: cont()}}}
			switch {
			case mode == "buf" || mode == "redact" || mode == "inject":
				resp.ModeOverride = &filterv3.ProcessingMode{RequestBodyMode: filterv3.ProcessingMode_BUFFERED}
			case mode == "streamredact":
				// Streamed, but held in ext_proc: the length will change, so
				// drop Content-Length before the headers go upstream.
				resp.ModeOverride = &filterv3.ProcessingMode{RequestBodyMode: filterv3.ProcessingMode_STREAMED}
				resp.GetRequestHeaders().Response.HeaderMutation = &extproc.HeaderMutation{RemoveHeaders: []string{"content-length"}}
			case mode == "stream" || mode == "streamcap":
				resp.ModeOverride = &filterv3.ProcessingMode{RequestBodyMode: filterv3.ProcessingMode_STREAMED}
			case mode == "partial":
				resp.ModeOverride = &filterv3.ProcessingMode{RequestBodyMode: filterv3.ProcessingMode_BUFFERED_PARTIAL}
			case mode == "sse":
				resp.ModeOverride = &filterv3.ProcessingMode{RequestBodyMode: filterv3.ProcessingMode_BUFFERED,
					ResponseHeaderMode: filterv3.ProcessingMode_SEND, ResponseBodyMode: filterv3.ProcessingMode_STREAMED}
			case strings.HasPrefix(mode, "hold"):
				secs, _ := strconv.Atoi(mode[strings.IndexByte(mode, ':')+1:])
				s.held.Add(1)
				if !strings.HasPrefix(mode, "holdnoover") {
					// Extend Envoy's timer for this message before holding it.
					if err := st.Send(&extproc.ProcessingResponse{
						OverrideMessageTimeout: durationpb.New(time.Duration(secs+5) * time.Second)}); err != nil {
						s.held.Add(-1)
						return err
					}
				}
				t := time.NewTimer(time.Duration(secs) * time.Second)
				select {
				case <-t.C:
				case <-st.Context().Done():
					s.held.Add(-1)
					log.Printf("held stream cancelled by Envoy: %v", st.Context().Err())
					return nil
				}
				s.held.Add(-1)
				if hdr(r.RequestHeaders.GetHeaders(), "x-deny") != "" {
					resp = deny("not approved")
				}
			}
		case *extproc.ProcessingRequest_RequestBody:
			s.bodies.Add(1)
			b := r.RequestBody.GetBody()
			cr := cont()
			switch mode {
			case "redact":
				nb := secret.ReplaceAll(b, []byte("[REDACTED]"))
				cr.BodyMutation = &extproc.BodyMutation{Mutation: &extproc.BodyMutation_Body{Body: nb}}
			case "inject":
				var m map[string]any
				if json.Unmarshal(b, &m) == nil {
					m["stream_options"] = map[string]any{"include_usage": true}
					nb, _ := json.Marshal(m)
					cr.BodyMutation = &extproc.BodyMutation{Mutation: &extproc.BodyMutation_Body{Body: nb}}
				}
			case "streamredact":
				// Keep each chunk back; release the whole body, redacted,
				// with the last one, so a match split across chunks is found.
				acc = append(acc, b...)
				out := []byte{}
				if r.RequestBody.GetEndOfStream() {
					out = secret.ReplaceAll(acc, []byte("[REDACTED]"))
					log.Printf("streamredact: %d bytes in, %d out", len(acc), len(out))
				}
				cr.BodyMutation = &extproc.BodyMutation{Mutation: &extproc.BodyMutation_Body{Body: out}}
			case "stream", "streamcap":
				seen += len(b)
				if mode == "streamcap" && seen > 1<<20 {
					log.Printf("streamcap: refusing at %d bytes", seen)
					if err := st.Send(deny("body over the 1 MiB cap")); err != nil {
						return err
					}
					continue
				}
				if r.RequestBody.GetEndOfStream() {
					log.Printf("streamed body: %d bytes", seen)
				}
			case "partial":
				log.Printf("partial body: %d bytes end_of_stream=%v", len(b), r.RequestBody.GetEndOfStream())
			}
			if m, ok := cr.BodyMutation.GetMutation().(*extproc.BodyMutation_Body); ok && mode != "streamredact" {
				// Buffered with a Content-Length: Envoy refuses a body of
				// another length unless the header is changed with it.
				cr.HeaderMutation = &extproc.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{{
					Header: &corev3.HeaderValue{Key: "content-length", RawValue: []byte(strconv.Itoa(len(m.Body)))}}}}
			}
			resp = &extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_RequestBody{
				RequestBody: &extproc.BodyResponse{Response: cr}}}
		case *extproc.ProcessingRequest_ResponseHeaders:
			resp = &extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_ResponseHeaders{
				ResponseHeaders: &extproc.HeadersResponse{Response: cont()}}}
		case *extproc.ProcessingRequest_ResponseBody:
			b := r.ResponseBody.GetBody()
			s.chunks.Add(1)
			if n := int64(len(b)); n > s.maxChunk.Load() {
				s.maxChunk.Store(n)
			}
			sse.feed(b)
			resp = &extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_ResponseBody{
				ResponseBody: &extproc.BodyResponse{Response: cont()}}}
		default:
			continue
		}
		if err := st.Send(resp); err != nil {
			return err
		}
	}
}

func deny(why string) *extproc.ProcessingResponse {
	return &extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_ImmediateResponse{
		ImmediateResponse: &extproc.ImmediateResponse{Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
			Body: []byte(why + "\n")}}}
}

// sseUsage reads token usage from an SSE stream fed in arbitrary chunks,
// in the Anthropic shape (message_start, message_delta) and the OpenAI
// shape (a final chunk with "usage").
type sseUsage struct {
	buf                 []byte
	events              int
	in, out             int64
	seenUsage           bool
	model               string
	splitLines, lastLen int
}

func (u *sseUsage) feed(b []byte) {
	if len(u.buf) > 0 {
		u.splitLines++
	}
	u.buf = append(u.buf, b...)
	for {
		i := bytes.IndexByte(u.buf, '\n')
		if i < 0 {
			return
		}
		line := strings.TrimRight(string(u.buf[:i]), "\r")
		u.buf = u.buf[i+1:]
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(line[5:])
		if data == "[DONE]" {
			continue
		}
		u.events++
		var ev struct {
			Type    string `json:"type"`
			Model   string `json:"model"`
			Message struct {
				Model string `json:"model"`
				Usage struct {
					In  int64 `json:"input_tokens"`
					Out int64 `json:"output_tokens"`
				} `json:"usage"`
			} `json:"message"`
			Usage *struct {
				In     int64 `json:"input_tokens"`
				Out    int64 `json:"output_tokens"`
				Prompt int64 `json:"prompt_tokens"`
				Compl  int64 `json:"completion_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal([]byte(data), &ev) != nil {
			continue
		}
		switch {
		case ev.Type == "message_start":
			u.model = ev.Message.Model
			u.in, u.out = ev.Message.Usage.In, ev.Message.Usage.Out
			u.seenUsage = true
		case ev.Type == "message_delta" && ev.Usage != nil:
			u.out = ev.Usage.Out // cumulative
			if ev.Usage.In > 0 {
				u.in = ev.Usage.In
			}
		case ev.Usage != nil:
			u.model = ev.Model
			u.in, u.out = ev.Usage.Prompt, ev.Usage.Compl
			u.seenUsage = true
		case ev.Model != "":
			u.model = ev.Model
		}
	}
}

func (u *sseUsage) summary() string {
	return fmt.Sprintf("model=%s events=%d usage_seen=%v in=%d out=%d lines_split_across_chunks=%d",
		u.model, u.events, u.seenUsage, u.in, u.out, u.splitLines)
}

func runExtproc(args []string) {
	fs := flag.NewFlagSet("extproc", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:19101", "")
	maxRecv := fs.Int("max-recv", 4<<20, "gRPC max receive message size")
	fs.Parse(args)
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	s := &srv{}
	g := grpc.NewServer(grpc.MaxRecvMsgSize(*maxRecv))
	extproc.RegisterExternalProcessorServer(g, s)
	go func() {
		for range time.Tick(2 * time.Second) {
			log.Printf("streams=%d held=%d bodies=%d resp_chunks=%d max_chunk=%d",
				s.streams.Load(), s.held.Load(), s.bodies.Load(), s.chunks.Load(), s.maxChunk.Load())
		}
	}()
	log.Fatal(g.Serve(l))
}

// ---- upstream ----

func runUpstream(args []string) {
	fs := flag.NewFlagSet("upstream", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:18101", "")
	fs.Parse(args)
	http.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sum := sha256.Sum256(b)
		out := map[string]any{"len": len(b), "sha": hex.EncodeToString(sum[:8]),
			"content_length": r.Header.Get("Content-Length"), "te": r.TransferEncoding}
		if len(b) < 512 {
			out["body"] = string(b)
		}
		json.NewEncoder(w).Encode(out)
	})
	http.HandleFunc("/anthropic", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		ev := func(name, data string) {
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, data)
			f.Flush()
			time.Sleep(20 * time.Millisecond)
		}
		ev("message_start", `{"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-5-5","usage":{"input_tokens":1234,"output_tokens":1}}}`)
		for i := 0; i < 20; i++ {
			ev("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"word%d "}}`, i))
		}
		ev("message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":321}}`)
		ev("message_stop", `{"type":"message_stop"}`)
	})
	http.HandleFunc("/openai", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			StreamOptions struct {
				IncludeUsage bool `json:"include_usage"`
			} `json:"stream_options"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		for i := 0; i < 20; i++ {
			fmt.Fprintf(w, "data: {\"id\":\"c1\",\"model\":\"gpt-5\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"w%d \"}}]}\n\n", i)
			f.Flush()
			time.Sleep(20 * time.Millisecond)
		}
		if req.StreamOptions.IncludeUsage {
			fmt.Fprint(w, "data: {\"id\":\"c1\",\"model\":\"gpt-5\",\"choices\":[],\"usage\":{\"prompt_tokens\":555,\"completion_tokens\":66}}\n\n")
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		f.Flush()
	})
	srv := &http.Server{Addr: *listen}
	log.Fatal(srv.ListenAndServe())
}

// ---- clients ----

func client(conns int) *http.Client {
	return &http.Client{Timeout: 10 * time.Minute, Transport: &http.Transport{
		MaxIdleConnsPerHost: conns, MaxConnsPerHost: 0, DisableCompression: true}}
}

func do(c *http.Client, url, mode string, body []byte, extra map[string]string) (int, string, time.Duration, error) {
	t := time.Now()
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("x-spike", mode)
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", time.Since(t), err
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(b), time.Since(t), nil
}

func runBench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	url := fs.String("url", "http://127.0.0.1:18100/echo", "")
	mode := fs.String("mode", "none", "")
	size := fs.Int("size", 1024, "body bytes")
	n := fs.Int("n", 200, "requests")
	body := fs.String("body", "", "literal body (overrides size)")
	show := fs.Bool("show", false, "print the last response")
	fs.Parse(args)
	b := []byte(*body)
	if *body == "" {
		b = bytes.Repeat([]byte("a"), *size)
	}
	c := client(4)
	var lat []time.Duration
	var last string
	codes := map[int]int{}
	for i := 0; i < *n; i++ {
		code, out, d, err := do(c, *url, *mode, b, nil)
		if err != nil {
			log.Fatal(err)
		}
		codes[code]++
		lat = append(lat, d)
		last = out
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	fmt.Printf("mode=%s size=%d n=%d codes=%v p50=%v p90=%v p99=%v\n", *mode, len(b), *n, codes,
		lat[len(lat)/2], lat[len(lat)*9/10], lat[len(lat)*99/100])
	if *show {
		fmt.Println(strings.TrimSpace(last))
	}
}

func runHold(args []string) {
	fs := flag.NewFlagSet("hold", flag.ExitOnError)
	url := fs.String("url", "http://127.0.0.1:18100/echo", "")
	n := fs.Int("n", 100, "held requests")
	secs := fs.Int("secs", 20, "hold for")
	mode := fs.String("mode", "hold", "hold or holdnoover")
	fs.Parse(args)
	c := client(*n + 8)
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[string]int{}
	start := time.Now()
	for i := 0; i < *n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, out, _, err := do(c, *url, fmt.Sprintf("%s:%d", *mode, *secs), []byte("x"), nil)
			k := strconv.Itoa(code)
			if err != nil {
				k = "err"
			} else if code != 200 {
				k += " " + strings.TrimSpace(firstLine(out))
			}
			mu.Lock()
			codes[k]++
			mu.Unlock()
		}()
	}
	time.Sleep(3 * time.Second)
	// While they are held: does a normal request still go through quickly?
	c2 := client(1)
	var probe []time.Duration
	for i := 0; i < 20; i++ {
		code, _, d, err := do(c2, *url, "none", []byte("x"), nil)
		if err != nil || code != 200 {
			fmt.Printf("probe: code=%d err=%v\n", code, err)
		}
		probe = append(probe, d)
	}
	sort.Slice(probe, func(i, j int) bool { return probe[i] < probe[j] })
	fmt.Printf("while %d held: probe p50=%v max=%v\n", *n, probe[10], probe[19])
	wg.Wait()
	fmt.Printf("held n=%d secs=%d mode=%s: results=%v after %v\n", *n, *secs, *mode, codes, time.Since(start).Round(time.Millisecond))
}

func firstLine(s string) string {
	sc := bufio.NewScanner(strings.NewReader(s))
	if sc.Scan() {
		return sc.Text()
	}
	return ""
}
