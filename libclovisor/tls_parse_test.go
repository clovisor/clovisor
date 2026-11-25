// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestTLSParseHTTP1(t *testing.T) {
	p := newTLSParser()
	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search","arguments":{"q":"secret"}}}`
	req := "POST /mcp?x=1 HTTP/1.1\r\nHost: Api.Example.com:443\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body
	if out := p.feed(1, 7, true, []byte(req), len(req)); len(out) != 0 {
		t.Fatalf("request completed without a response: %v", out)
	}
	p.feed(1, 7, true, []byte("more body that is not a request"), 31)
	p.feed(1, 7, true, []byte("GET /b HTTP/1.1\r\nHost: api.example.com\r\n\r\n"), 41)
	if out := p.feed(1, 7, false, []byte("HTTP/1.1 100 Continue\r\n\r\n"), 25); len(out) != 0 {
		t.Fatalf("interim response completed a request: %v", out)
	}
	out := p.feed(1, 7, false, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), 41)
	if len(out) != 1 || out[0].Method != "POST" || out[0].Host != "api.example.com" || out[0].Path != "/mcp" ||
		out[0].Status != 200 || out[0].MCPMethod != "tools/call" || out[0].Tool != "search" {
		t.Fatalf("first: %+v", out)
	}
	if strings.Contains(strings.Join([]string{out[0].Method, out[0].Path, out[0].Tool}, ""), "secret") {
		t.Error("arguments kept")
	}
	// A request with no response yet is reported when the process exits.
	rest := p.close(1)
	if len(rest) != 1 || rest[0].Path != "/b" || rest[0].Status != 0 {
		t.Errorf("at close: %+v", rest)
	}
	if len(p.conns) != 0 {
		t.Error("connections kept after close")
	}
}

// h2Write builds what a client writes: the preface (if first), then a
// HEADERS frame for each request, and DATA.
func h2Frames(t *testing.T, enc *hpack.Encoder, hbuf *bytes.Buffer, stream uint32, fields [][2]string, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	fr := http2.NewFramer(&out, nil)
	hbuf.Reset()
	for _, f := range fields {
		enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: hbuf.Bytes(), EndHeaders: true, EndStream: data == nil}); err != nil {
		t.Fatal(err)
	}
	if data != nil {
		fr.WriteData(stream, true, data)
	}
	return out.Bytes()
}

func TestTLSParseHTTP2(t *testing.T) {
	p := newTLSParser()
	var wb, rb bytes.Buffer
	wenc, renc := hpack.NewEncoder(&wb), hpack.NewEncoder(&rb)
	var settings bytes.Buffer
	http2.NewFramer(&settings, nil).WriteSettings()

	first := append(append(append([]byte{}, h2Preface...), settings.Bytes()...),
		h2Frames(t, wenc, &wb, 1, [][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", "mcp.example.com"}, {":path", "/mcp"}},
			[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))...)
	p.feed(2, 9, true, first, len(first))

	// A second request whose HEADERS frame arrives split across two calls,
	// after a large DATA frame of which only the start was captured.
	big := bytes.Repeat([]byte("x"), 100000)
	upload := h2Frames(t, wenc, &wb, 3, [][2]string{{":method", "PUT"}, {":scheme", "https"}, {":authority", "mcp.example.com"}, {":path", "/upload?k=v"}}, big)
	// The HEADERS frame of stream 3 in one call, then its DATA cut off at
	// the capture limit.
	hdrLen := 9 + int(upload[0])<<16 | int(upload[1])<<8 | int(upload[2])
	p.feed(2, 9, true, upload[:hdrLen/2], hdrLen/2)
	p.feed(2, 9, true, upload[hdrLen/2:hdrLen], hdrLen-hdrLen/2)
	p.feed(2, 9, true, upload[hdrLen:hdrLen+2048], len(upload)-hdrLen)
	third := h2Frames(t, wenc, &wb, 5, [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "mcp.example.com"}, {":path", "/c"}}, nil)
	p.feed(2, 9, true, third, len(third))

	var reads []byte
	reads = append(reads, settings.Bytes()...)
	reads = append(reads, h2Frames(t, renc, &rb, 1, [][2]string{{":status", "200"}}, []byte("{}"))...)
	reads = append(reads, h2Frames(t, renc, &rb, 5, [][2]string{{":status", "404"}}, nil)...)
	reads = append(reads, h2Frames(t, renc, &rb, 3, [][2]string{{":status", "201"}}, nil)...)
	var out []TLSRequest
	for i := 0; i < len(reads); i += 7 { // read in small pieces
		j := min(i+7, len(reads))
		out = append(out, p.feed(2, 9, false, reads[i:j], j-i)...)
	}
	got := map[string]TLSRequest{}
	for _, r := range out {
		got[r.Path] = r
	}
	if r := got["/mcp"]; r.Method != "POST" || r.Status != 200 || r.Proto != "HTTP/2" || r.MCPMethod != "tools/list" || r.Host != "mcp.example.com" {
		t.Errorf("/mcp: %+v", r)
	}
	if r := got["/upload"]; r.Method != "PUT" || r.Status != 201 {
		t.Errorf("/upload: %+v", r)
	}
	if r := got["/c"]; r.Status != 404 {
		t.Errorf("/c: %+v", r)
	}
	c := p.conns[tlsConnKey{2, 9}]
	if c.w.errs != 0 || c.r.errs != 0 {
		t.Errorf("hpack errors: %d %d", c.w.errs, c.r.errs)
	}
}
