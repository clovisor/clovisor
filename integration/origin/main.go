// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

// Command origin is the integration tests' destination: one TLS server
// for every test hostname, so the tests need no internet.
//
//	origin.test  /allowed, /secret, /headers, and a git repository over
//	             git's dumb HTTP protocol under /repo.git/
//	mcp.test     a remote MCP server (streamable HTTP, JSON responses) at /mcp
//	other.test   anything; the test profile does not allow it
//
// With -banner it also serves raw TCP that speaks first, like SSH, and
// with -udp-echo a UDP echo, for the transparent-mode tests.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
)

var (
	listen = flag.String("listen", ":443", "address")
	cert   = flag.String("cert", "/origin/tls.crt", "certificate")
	key    = flag.String("key", "/origin/tls.key", "key")
	repo   = flag.String("repo", "/origin/repo.git", "bare git repository, prepared with git update-server-info")
	desc   = flag.String("desc-suffix", "", "appended to tool descriptions, to simulate a server changing its tools")
	banner = flag.String("banner", "", "also serve raw TCP here that sends a banner first, like SSH")
	echo   = flag.String("udp-echo", "", "also echo UDP datagrams here (comma-separated)")
)

func main() {
	flag.Parse()
	if *banner != "" {
		ln, err := net.Listen("tcp", *banner)
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				io.WriteString(c, "SSH-2.0-origin\r\n")
				c.Close()
			}
		}()
	}
	for _, addr := range strings.Split(*echo, ",") {
		if addr == "" {
			continue
		}
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			buf := make([]byte, 2048)
			for {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				pc.WriteTo(buf[:n], from)
			}
		}()
	}
	files := http.StripPrefix("/repo.git/", http.FileServer(http.Dir(*repo)))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if i := strings.LastIndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		switch {
		case host == "mcp.test" && r.URL.Path == "/mcp":
			serveMCP(w, r)
		case strings.HasPrefix(r.URL.Path, "/repo.git/"):
			files.ServeHTTP(w, r)
		case r.URL.Path == "/echo":
			// What arrived: the body, and how it was framed.
			b, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"len": len(b), "content_length": r.Header.Get("Content-Length"),
				"chunked": len(r.TransferEncoding) > 0, "body": string(b[:min(len(b), 256)])})
		case r.URL.Path == "/v1/messages" || r.URL.Path == "/v1/chat/completions":
			serveModel(w, r)
		case r.URL.Path == "/headers":
			hs := map[string]string{}
			for k, v := range r.Header {
				hs[strings.ToLower(k)] = strings.Join(v, ",")
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(hs)
		default:
			io.WriteString(w, host+" "+r.Method+" "+r.URL.Path+"\n")
		}
	})
	log.Fatal(http.ListenAndServeTLS(*listen, *cert, *key, h))
}

type rpc struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

var tools = []string{"search", "get_file", "delete_repo", "summarize"}

func serveMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var m rpc
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(m.ID) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var result interface{}
	switch m.Method {
	case "initialize":
		w.Header().Set("Mcp-Session-Id", "it-session")
		result = map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{"tools": map[string]interface{}{}},
			"serverInfo": map[string]string{"name": "origin", "version": "1"}}
	case "tools/list":
		var ts []map[string]interface{}
		for _, n := range tools {
			ts = append(ts, map[string]interface{}{"name": n, "description": n + *desc, "inputSchema": map[string]string{"type": "object"}})
		}
		result = map[string]interface{}{"tools": ts}
	case "tools/call":
		var p struct {
			Name string `json:"name"`
		}
		json.Unmarshal(m.Params, &p)
		result = map[string]interface{}{"content": []map[string]string{{"type": "text", "text": "origin ran " + p.Name}}}
		if p.Name == "summarize" {
			// An event stream: a sampling request to the client, then the
			// result (milestone 5.5's sampling: ask).
			w.Header().Set("Content-Type", "text/event-stream")
			sampling, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": "srv-1", "method": "sampling/createMessage",
				"params": map[string]interface{}{"maxTokens": 50, "messages": []map[string]interface{}{
					{"role": "user", "content": map[string]string{"type": "text", "text": "Summarize the repository"}}}}})
			done, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": m.ID, "result": result})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sampling)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", done)
			return
		}
	default:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": m.ID, "error": map[string]interface{}{"code": -32601, "message": "unknown method"}})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": m.ID, "result": result})
}

// serveModel is a model API shaped like Anthropic's messages or OpenAI's
// chat completions (milestone 5.4): 100 input tokens (40 for OpenAI),
// max_tokens output tokens, streamed or not. The reply's text says what
// arrived: whether include_usage was set, and the Accept-Encoding.
func serveModel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Model         string `json:"model"`
		Stream        bool   `json:"stream"`
		MaxTokens     int    `json:"max_tokens"`
		StreamOptions *struct {
			IncludeUsage bool `json:"include_usage"`
		} `json:"stream_options"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.MaxTokens == 0 {
		req.MaxTokens = 50
	}
	usage := req.StreamOptions != nil && req.StreamOptions.IncludeUsage
	text := fmt.Sprintf("include_usage=%v accept-encoding=%q", usage, r.Header.Get("Accept-Encoding"))
	flush := func() {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	event := func(name string, v interface{}) {
		b, _ := json.Marshal(v)
		if name != "" {
			fmt.Fprintf(w, "event: %s\n", name)
		}
		fmt.Fprintf(w, "data: %s\n\n", b)
		flush()
	}
	type obj = map[string]interface{}
	anthropic := r.URL.Path == "/v1/messages"
	switch {
	case anthropic && !req.Stream:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(obj{"type": "message", "model": req.Model, "content": []obj{{"type": "text", "text": text}},
			"usage": obj{"input_tokens": 100, "output_tokens": req.MaxTokens}})
	case anthropic:
		w.Header().Set("Content-Type", "text/event-stream")
		event("message_start", obj{"type": "message_start", "message": obj{"model": req.Model, "usage": obj{"input_tokens": 100, "output_tokens": 1}}})
		event("content_block_delta", obj{"type": "content_block_delta", "delta": obj{"type": "text_delta", "text": text}})
		event("message_delta", obj{"type": "message_delta", "usage": obj{"output_tokens": req.MaxTokens}})
		event("message_stop", obj{"type": "message_stop"})
	case !req.Stream:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(obj{"model": req.Model, "choices": []obj{{"message": obj{"content": text}}},
			"usage": obj{"prompt_tokens": 40, "completion_tokens": req.MaxTokens}})
	default:
		w.Header().Set("Content-Type", "text/event-stream")
		var u interface{}
		event("", obj{"model": req.Model, "choices": []obj{{"delta": obj{"content": text}}}, "usage": u})
		if usage {
			event("", obj{"model": req.Model, "choices": []obj{}, "usage": obj{"prompt_tokens": 40, "completion_tokens": req.MaxTokens}})
		}
		io.WriteString(w, "data: [DONE]\n\n")
	}
}
