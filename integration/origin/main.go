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

var tools = []string{"search", "get_file", "delete_repo"}

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
	default:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": m.ID, "error": map[string]interface{}{"code": -32601, "message": "unknown method"}})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": m.ID, "result": result})
}
