// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strconv"
	"strings"

	"golang.org/x/net/http2/hpack"
)

// TLS plaintext parsing (milestone 6.2): what the uprobes copied from a
// process's TLS calls, turned into requests. Each call's capture is
// bounded (6.0), so the parser keeps per-connection state: HTTP/1.1 from
// the start of each call, HTTP/2 frames across calls, skipping what a
// call wrote past its capture. Only the request line, the host, the
// status and an MCP call's method and tool are kept; bodies never are.

// TLSRequest is one request seen in a process's TLS plaintext.
type TLSRequest struct {
	Proto  string // HTTP/1.1 or HTTP/2
	Method string
	Host   string // Host or :authority, without a default port
	Path   string // without the query string
	Status int    // 0: no response seen
	// MCPMethod and Tool are a JSON-RPC request's method and, for
	// tools/call, the tool's name, where the call's capture held them.
	MCPMethod string `json:",omitempty"`
	Tool      string `json:",omitempty"`
}

// tlsParser holds the state of every connection seen in TLS plaintext.
type tlsParser struct {
	conns map[tlsConnKey]*tlsConn
}

type tlsConnKey struct {
	pid uint32
	obj uint64
}

type tlsConn struct {
	h2      bool
	w, r    tlsDir
	pending []*TLSRequest          // HTTP/1.1, in order
	streams map[uint32]*TLSRequest // HTTP/2, by stream
	bodied  map[uint32]bool        // HTTP/2 streams whose first DATA was looked at
}

type tlsDir struct {
	buf  []byte // a partial frame header, or a HEADERS payload in progress
	skip int    // bytes of the current frame still to come and not needed
	dec  *hpack.Decoder
	errs int
	// broken: frame boundaries were lost, so nothing more is parsed in
	// this direction.
	broken bool
}

// lose accounts for n bytes of the stream the capture did not hold: the
// rest of a call longer than its capture. They belong to the frame being
// skipped, or the one being assembled; beyond that, sync is lost.
func (d *tlsDir) lose(n int) {
	if len(d.buf) > 0 {
		// A frame header, or a header block, cut off: frame sync or
		// HPACK's table is lost, and later headers could decode wrongly.
		d.errs++
		d.broken, d.buf = true, nil
		return
	}
	if n <= d.skip {
		d.skip -= n
		return
	}
	d.broken, d.buf = true, nil
}

// maxTLSConns bounds the connections tracked per node.
const maxTLSConns = 16384

var h2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

func newTLSParser() *tlsParser { return &tlsParser{conns: map[tlsConnKey]*tlsConn{}} }

// feed parses one call's capture: data is what was copied, total what the
// call wrote or read. It returns requests completed by a response.
func (p *tlsParser) feed(pid uint32, obj uint64, write bool, data []byte, total int) []TLSRequest {
	k := tlsConnKey{pid, obj}
	c := p.conns[k]
	if c == nil {
		if len(p.conns) >= maxTLSConns {
			return nil
		}
		c = &tlsConn{streams: map[uint32]*TLSRequest{}, bodied: map[uint32]bool{}}
		c.w.dec = hpack.NewDecoder(65536, nil)
		c.r.dec = hpack.NewDecoder(65536, nil)
		p.conns[k] = c
	}
	if write && !c.h2 && bytes.HasPrefix(data, h2Preface) {
		c.h2 = true
		data = data[len(h2Preface):]
		total -= len(h2Preface)
	}
	if !c.h2 {
		return c.h1(write, data)
	}
	d := &c.r
	if write {
		d = &c.w
	}
	if d.broken {
		return nil
	}
	var out []TLSRequest
	c.frames(d, write, data, &out)
	if lost := total - len(data); lost > 0 {
		d.lose(lost)
	}
	return out
}

// close ends a process's connections, reporting requests with no
// response.
func (p *tlsParser) close(pid uint32) []TLSRequest {
	var out []TLSRequest
	for k, c := range p.conns {
		if k.pid != pid {
			continue
		}
		for _, r := range c.pending {
			out = append(out, *r)
		}
		for _, r := range c.streams {
			out = append(out, *r)
		}
		delete(p.conns, k)
	}
	return out
}

func (c *tlsConn) h1(write bool, data []byte) []TLSRequest {
	head := data
	end := bytes.Index(data, []byte("\r\n\r\n"))
	if end >= 0 {
		head = data[:end]
	}
	lines := strings.Split(string(head), "\r\n")
	f := strings.Fields(lines[0])
	if write {
		if len(f) != 3 || !strings.HasPrefix(f[2], "HTTP/1.") || !isMethod(f[0]) {
			return nil // not the start of a request: a body, most likely
		}
		r := &TLSRequest{Proto: "HTTP/1.1", Method: f[0], Path: pathOnly(f[1])}
		var ctype string
		clen := -1
		for _, l := range lines[1:] {
			k, v, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			switch strings.ToLower(strings.TrimSpace(k)) {
			case "host":
				r.Host = hostOnly(v)
			case "content-type":
				ctype = v
			case "content-length":
				clen, _ = strconv.Atoi(v)
			}
		}
		if end >= 0 && clen > 0 && strings.Contains(ctype, "json") && end+4+clen <= len(data) {
			r.MCPMethod, r.Tool = jsonRPC(data[end+4 : end+4+clen])
		}
		if len(c.pending) < 64 {
			c.pending = append(c.pending, r)
		}
		return nil
	}
	if len(f) < 2 || !strings.HasPrefix(f[0], "HTTP/1.") || len(c.pending) == 0 {
		return nil
	}
	st, err := strconv.Atoi(f[1])
	if err != nil {
		return nil
	}
	if st >= 100 && st < 200 {
		return nil // interim: the final status follows
	}
	r := c.pending[0]
	c.pending = c.pending[1:]
	r.Status = st
	return []TLSRequest{*r}
}

func (c *tlsConn) frames(d *tlsDir, write bool, data []byte, out *[]TLSRequest) {
	for len(data) > 0 {
		if d.skip > 0 {
			n := min(d.skip, len(data))
			d.skip -= n
			data = data[n:]
			continue
		}
		d.buf = append(d.buf, data...)
		data = nil
		for len(d.buf) >= 9 {
			n := int(d.buf[0])<<16 | int(d.buf[1])<<8 | int(d.buf[2])
			typ, flags := d.buf[3], d.buf[4]
			stream := binary.BigEndian.Uint32(d.buf[5:9]) & 0x7fffffff
			switch typ {
			case 0x1, 0x9: // HEADERS, CONTINUATION
				if len(d.buf) < 9+n {
					if n > 1<<16 {
						d.errs++ // too large to wait for
						d.skip, d.buf = 9+n-len(d.buf), nil
					}
					goto more
				}
				p := d.buf[9 : 9+n]
				if typ == 0x1 {
					if flags&0x8 != 0 && len(p) > 0 { // PADDED
						pad := int(p[0])
						if pad >= len(p) {
							p = nil
						} else {
							p = p[1 : len(p)-pad]
						}
					}
					if flags&0x20 != 0 && len(p) >= 5 { // PRIORITY
						p = p[5:]
					}
				}
				if fields, err := d.dec.DecodeFull(p); err != nil {
					d.errs++
				} else {
					c.headers(write, stream, fields, out)
				}
				d.buf = d.buf[9+n:]
			case 0x0: // DATA: the first of a request's, for an MCP call
				r := c.streams[stream]
				if write && r != nil && !c.bodied[stream] && len(d.buf) >= 9+n {
					c.bodied[stream] = true
					p := d.buf[9 : 9+n]
					if flags&0x8 != 0 && len(p) > 0 {
						if pad := int(p[0]); pad < len(p) {
							p = p[1 : len(p)-pad]
						}
					}
					r.MCPMethod, r.Tool = jsonRPC(p)
				}
				fallthrough
			default:
				if have := len(d.buf) - 9; have >= n {
					d.buf = d.buf[9+n:]
					continue
				} else {
					d.skip, d.buf = n-have, nil
				}
				goto more
			}
		}
	more:
		if len(d.buf) == 0 {
			d.buf = nil
		}
	}
}

func (c *tlsConn) headers(write bool, stream uint32, fields []hpack.HeaderField, out *[]TLSRequest) {
	get := func(name string) string {
		for _, f := range fields {
			if f.Name == name {
				return f.Value
			}
		}
		return ""
	}
	if write {
		if m := get(":method"); m != "" && len(c.streams) < 256 {
			c.streams[stream] = &TLSRequest{Proto: "HTTP/2", Method: m, Host: hostOnly(get(":authority")), Path: pathOnly(get(":path"))}
		}
		return
	}
	st, err := strconv.Atoi(get(":status"))
	if err != nil || (st >= 100 && st < 200) {
		return
	}
	if r := c.streams[stream]; r != nil {
		r.Status = st
		*out = append(*out, *r)
		delete(c.streams, stream)
		delete(c.bodied, stream)
	}
}

// jsonRPC reads a JSON-RPC request's method and, for tools/call, its
// tool's name. Anything else in the body is not kept.
func jsonRPC(b []byte) (method, tool string) {
	var m struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		Params  struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if json.Unmarshal(b, &m) != nil || m.JSONRPC != "2.0" || m.Method == "" {
		return "", ""
	}
	if m.Method == "tools/call" {
		return m.Method, m.Params.Name
	}
	return m.Method, ""
}

func isMethod(s string) bool {
	switch s {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
		return true
	}
	return false
}

func pathOnly(target string) string {
	if i := strings.IndexAny(target, "?#"); i >= 0 {
		target = target[:i]
	}
	return target
}

func hostOnly(h string) string {
	h = strings.ToLower(h)
	if strings.HasSuffix(h, ":443") {
		h = strings.TrimSuffix(h, ":443")
	}
	return h
}
