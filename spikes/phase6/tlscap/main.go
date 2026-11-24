// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

// Phase 6 spike: TLS plaintext from uprobes (see ../README.md).
//
//	tlscap server                  HTTPS on :8443 (HTTP/1.1 and 2), a TLS sink on :8444
//	tlscap probe -obj ... [-go b]  attach, decode what runs in /sys/fs/cgroup/spike6 send
//	tlscap goclient -url u -n N    a Go client (HTTP/2), to build with two Go versions
//	tlscap gobench -n N -size S    N writes of S bytes to the sink, timed
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/elf"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/net/http2/hpack"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: tlscap server|probe|goclient|gobench")
	}
	switch os.Args[1] {
	case "server":
		server()
	case "probe":
		probe(os.Args[2:])
	case "goclient":
		goclient(os.Args[2:])
	case "gobench":
		gobench(os.Args[2:])
	default:
		log.Fatalf("unknown %q", os.Args[1])
	}
}

func cert() tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	t := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour * 24)}
	der, _ := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func server() {
	c := cert()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/big" {
			w.Write(bytes.Repeat([]byte("x"), 1<<20))
			return
		}
		fmt.Fprintf(w, "%s %s %s\n", r.Proto, r.Method, r.URL.Path)
	})
	s := &http.Server{Addr: ":8443", Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{c}}}
	go func() {
		l, err := tls.Listen("tcp", ":8444", &tls.Config{Certificates: []tls.Certificate{c}})
		if err != nil {
			log.Fatal(err)
		}
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(io.Discard, conn); conn.Close() }()
		}
	}()
	log.Fatal(s.ListenAndServeTLS("", ""))
}

func goclient(args []string) {
	fs := flag.NewFlagSet("goclient", flag.ExitOnError)
	u := fs.String("url", "https://localhost:8443/go", "")
	n := fs.Int("n", 3, "")
	fs.Parse(args)
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}}
	for i := 0; i < *n; i++ {
		r, err := cl.Post(fmt.Sprintf("%s/%d", *u, i), "text/plain", strings.NewReader("hello"))
		if err != nil {
			log.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		fmt.Printf("%s", b)
	}
}

func gobench(args []string) {
	fs := flag.NewFlagSet("gobench", flag.ExitOnError)
	n := fs.Int("n", 100000, "")
	size := fs.Int("size", 64, "")
	fs.Parse(args)
	c, err := tls.Dial("tcp", "localhost:8444", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Fatal(err)
	}
	b := bytes.Repeat([]byte("y"), *size)
	t0 := time.Now()
	for i := 0; i < *n; i++ {
		if _, err := c.Write(b); err != nil {
			log.Fatal(err)
		}
	}
	d := time.Since(t0)
	fmt.Printf("go writes=%d size=%d total=%v per=%v MB/s=%.1f\n", *n, *size, d, d/time.Duration(*n),
		float64(*n**size)/d.Seconds()/1e6)
}

// ---- probe ----

const capLen = 4096

var attachTook time.Duration

type event struct {
	Kind, Lib, Pid, Tid uint32
	Obj                 uint64
	Len, Caplen         uint32
	Fd                  int32
	Pad                 uint32
	Data                [capLen]byte
}

type config struct {
	CgID    uint64
	CgLevel uint32
	Capture uint16
	Hold    uint16
}

func probe(args []string) {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	obj := fs.String("obj", "bpf/tlscap.o", "")
	libssl := fs.String("libssl", "/usr/lib/aarch64-linux-gnu/libssl.so.3", "")
	gobins := fs.String("go", "", "comma-separated Go binaries to hook")
	gnutls := fs.String("gnutls", "/usr/lib/aarch64-linux-gnu/libgnutls.so.30", "")
	capture := fs.Bool("capture", true, "copy plaintext (false: count calls only)")
	quiet := fs.Bool("quiet", false, "no per-event output")
	notp := fs.Bool("notp", false, "no syscall tracepoints (no fd correlation)")
	pid := fs.Int("pid", 0, "attach the library probes to this process only")
	follow := fs.Bool("follow", false, "attach the library probes to each process as it execs in the cgroup")
	hold := fs.Bool("hold", false, "with -follow: stop each process at exec until attached")
	fs.Parse(args)

	cg := "/sys/fs/cgroup/spike6"
	os.Mkdir(cg, 0o755)
	var st syscall.Stat_t
	if err := syscall.Stat(cg, &st); err != nil {
		log.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(*obj)
	if err != nil {
		log.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("%+v", ve)
		}
		log.Fatal(err)
	}
	defer coll.Close()
	c := config{CgID: st.Ino, CgLevel: 1}
	if *capture {
		c.Capture = 1
	}
	if *hold {
		c.Hold = 1
	}
	if err := coll.Maps["cfg"].Put(uint32(0), c); err != nil {
		log.Fatal(err)
	}
	var links []link.Link
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()
	add := func(l link.Link, err error, what string) {
		if err != nil {
			log.Printf("attach %s: %v", what, err)
			return
		}
		links = append(links, l)
	}
	t0 := time.Now()
	ex, err := link.OpenExecutable(*libssl)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { log.Printf("libssl probes attached in %v", attachTook) }()
	attachSSL := func(pid int) {
		for sym, prog := range map[string]string{"SSL_write": "ssl_write", "SSL_write_ex": "ssl_write_ex", "SSL_read": "ssl_read", "SSL_read_ex": "ssl_read_ex"} {
			l, err := ex.Uprobe(sym, coll.Programs[prog], &link.UprobeOptions{PID: pid})
			add(l, err, sym)
			l, err = ex.Uretprobe(sym, coll.Programs[prog+"_ret"], &link.UprobeOptions{PID: pid})
			add(l, err, sym+" ret")
		}
	}
	if *follow {
		l, err := link.Tracepoint("sched", "sched_process_exec", coll.Programs["tp_exec"], nil)
		add(l, err, "exec")
	} else {
		attachSSL(*pid)
	}
	attachTook = time.Since(t0)
	if *gnutls != "" {
		gx, err := link.OpenExecutable(*gnutls)
		if err != nil {
			log.Fatal(err)
		}
		for sym, prog := range map[string]string{"gnutls_record_send": "gnutls_send", "gnutls_record_recv": "gnutls_recv"} {
			l, err := gx.Uprobe(sym, coll.Programs[prog], nil)
			add(l, err, sym)
			l, err = gx.Uretprobe(sym, coll.Programs[prog+"_ret"], nil)
			add(l, err, sym+" ret")
		}
	}
	for _, tp := range []string{"write", "read", "sendto", "recvfrom", "sendmsg", "recvmsg"} {
		if *notp {
			break
		}
		l, err := link.Tracepoint("syscalls", "sys_enter_"+tp, coll.Programs["tp_"+tp], nil)
		add(l, err, tp)
	}
	for _, b := range strings.Split(*gobins, ",") {
		if b == "" {
			continue
		}
		if err := hookGo(b, coll, add); err != nil {
			log.Printf("go %s: %v", b, err)
		}
	}
	log.Printf("attached %d links; run things in %s", len(links), cg)

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		log.Fatal(err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; rd.Close() }()

	streams := map[string]*h2stream{}
	fds := map[uint64]int32{}
	var nev, bytesCap, truncated int
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		var e event
		raw := rec.RawSample
		if len(raw) < 40 {
			continue
		}
		binary.Read(bytes.NewReader(append(raw, make([]byte, binary.Size(e)-len(raw))...)), binary.LittleEndian, &e)
		nev++
		if e.Kind == 4 {
			t := time.Now()
			attachSSL(int(e.Pid))
			if *hold {
				syscall.Kill(int(e.Pid), syscall.SIGCONT)
			}
			fmt.Printf("exec pid=%d %s: attached in %v\n", e.Pid, comm(e.Pid), time.Since(t))
			continue
		}
		if e.Kind == 3 {
			fds[e.Obj] = e.Fd
			if !*quiet {
				fmt.Printf("pid=%d obj=%#x fd=%d (%s)\n", e.Pid, e.Obj, e.Fd, peer(e.Pid, e.Fd))
			}
			continue
		}
		data := e.Data[:e.Caplen]
		bytesCap += int(e.Caplen)
		if e.Len > e.Caplen {
			truncated++
		}
		dir := map[uint32]string{1: "write", 2: "read"}[e.Kind]
		lib := map[uint32]string{1: "libssl", 2: "go", 3: "gnutls"}[e.Lib]
		key := fmt.Sprintf("%d/%x/%s", e.Pid, e.Obj, dir)
		s := streams[key]
		if s == nil {
			s = &h2stream{dec: hpack.NewDecoder(65536, nil)}
			streams[key] = s
		}
		for _, line := range s.feed(data, int(e.Len)) {
			if !*quiet {
				fmt.Printf("%s %s pid=%d %s fd=%d: %s\n", comm(e.Pid), lib, e.Pid, dir, e.Fd, line)
			}
		}
	}
	var sum [3]uint64
	var per []uint64
	if err := coll.Maps["calls"].Lookup(uint32(0), &per); err == nil {
		for _, v := range per {
			sum[0] += v
		}
	}
	if err := coll.Maps["calls"].Lookup(uint32(1), &per); err == nil {
		for _, v := range per {
			sum[1] += v
		}
	}
	if err := coll.Maps["calls"].Lookup(uint32(2), &per); err == nil {
		for _, v := range per {
			sum[2] += v
		}
	}
	h2errs := 0
	for _, s := range streams {
		h2errs += s.errs
	}
	fmt.Printf("events=%d writes=%d reads=%d ringbuf-full=%d captured=%dB truncated-calls=%d hpack-errors=%d\n",
		nev, sum[0], sum[1], sum[2], bytesCap, truncated, h2errs)
}

func comm(pid uint32) string {
	b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if len(b) == 0 {
		return "?"
	}
	return strings.TrimSpace(string(b))
}

func peer(pid uint32, fd int32) string {
	l, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil {
		return "gone"
	}
	return l
}

// hookGo attaches to crypto/tls.(*Conn).Write and Read: at entry, and at
// each return instruction (arm64 RET, 0xd65f03c0) instead of a uretprobe.
func hookGo(path string, coll *ebpf.Collection, add func(link.Link, error, string)) error {
	f, err := elf.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	syms, err := f.Symbols()
	if err != nil {
		return fmt.Errorf("no symbols (stripped?): %w", err)
	}
	ex, err := link.OpenExecutable(path)
	if err != nil {
		return err
	}
	text := f.Section(".text")
	body, err := text.Data()
	if err != nil {
		return err
	}
	found := 0
	for _, s := range syms {
		var entry, ret string
		switch s.Name {
		case "crypto/tls.(*Conn).Write":
			entry, ret = "go_write", "go_write_ret"
		case "crypto/tls.(*Conn).Read":
			entry, ret = "go_read", "go_read_ret"
		default:
			continue
		}
		found++
		l, err := ex.Uprobe(s.Name, coll.Programs[entry], nil)
		add(l, err, s.Name)
		start := s.Value - text.Addr
		var rets int
		for off := uint64(0); off+4 <= s.Size; off += 4 {
			if binary.LittleEndian.Uint32(body[start+off:]) == 0xd65f03c0 {
				l, err := ex.Uprobe(s.Name, coll.Programs[ret], &link.UprobeOptions{Offset: off})
				add(l, err, s.Name+"+"+strconv.FormatUint(off, 16))
				rets++
			}
		}
		log.Printf("go %s: %s, %d return instructions", filepath.Base(path), s.Name, rets)
	}
	if found == 0 {
		return errors.New("crypto/tls.(*Conn) Read/Write not found")
	}
	return nil
}

// h2stream turns one direction of one TLS connection into request and
// response lines: HTTP/1.x from the start of each call, HTTP/2 frames
// across calls. A call longer than the capture leaves the rest of its
// frame to skip.
type h2stream struct {
	h2    bool
	buf   []byte // a partial frame header, or a HEADERS payload in progress
	skip  int    // bytes of the current frame not captured or not needed
	dec   *hpack.Decoder
	errs  int
	lines []string
}

var preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

func (s *h2stream) feed(data []byte, total int) []string {
	s.lines = nil
	lost := total - len(data)
	if !s.h2 {
		if bytes.HasPrefix(data, preface) {
			s.h2 = true
			data = data[len(preface):]
		} else if len(data) >= 9 && looksH2(data) {
			s.h2 = true // a read: the server's SETTINGS
		} else {
			if i := bytes.Index(data, []byte("\r\n")); i > 0 && bytes.Contains(data[:i], []byte("HTTP/1")) {
				line := string(data[:i])
				if h := header(data, "Host"); h != "" {
					line += " host=" + h
				}
				s.lines = append(s.lines, "h1 "+line)
			}
			return s.lines
		}
	}
	s.frames(data)
	if lost > 0 {
		// What was not captured belongs to the frame in progress (or
		// later ones): skip it, and lose sync if a header was in it.
		if len(s.buf) > 0 {
			s.errs++
			s.buf = nil
		}
		s.skip += lost
	}
	return s.lines
}

func looksH2(b []byte) bool {
	return b[3] == 0x4 && b[5]&0x80 == 0 // a SETTINGS frame on stream 0
}

func (s *h2stream) frames(data []byte) {
	for len(data) > 0 {
		if s.skip > 0 {
			n := min(s.skip, len(data))
			s.skip -= n
			data = data[n:]
			continue
		}
		s.buf = append(s.buf, data...)
		data = nil
		for len(s.buf) >= 9 {
			n := int(s.buf[0])<<16 | int(s.buf[1])<<8 | int(s.buf[2])
			typ, flags := s.buf[3], s.buf[4]
			stream := binary.BigEndian.Uint32(s.buf[5:9]) & 0x7fffffff
			if typ != 0x1 && typ != 0x9 { // not HEADERS or CONTINUATION: skip
				have := len(s.buf) - 9
				if have >= n {
					s.buf = s.buf[9+n:]
					continue
				}
				s.skip = n - have
				s.buf = nil
				break
			}
			if len(s.buf) < 9+n {
				break // wait for the rest
			}
			p := s.buf[9 : 9+n]
			if typ == 0x1 {
				if flags&0x8 != 0 && len(p) > 0 { // PADDED
					pad := int(p[0])
					p = p[1 : len(p)-pad]
				}
				if flags&0x20 != 0 && len(p) >= 5 { // PRIORITY
					p = p[5:]
				}
			}
			fields, err := s.dec.DecodeFull(p)
			if err != nil {
				s.errs++
			} else {
				var parts []string
				for _, f := range fields {
					if strings.HasPrefix(f.Name, ":") {
						parts = append(parts, f.Name+"="+f.Value)
					}
				}
				s.lines = append(s.lines, fmt.Sprintf("h2 stream=%d %s", stream, strings.Join(parts, " ")))
			}
			s.buf = s.buf[9+n:]
		}
		if len(s.buf) == 0 {
			s.buf = nil
		}
	}
}

func header(b []byte, name string) string {
	for _, l := range strings.Split(string(b), "\r\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(k, name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
