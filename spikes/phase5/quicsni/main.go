// Command quicsni is the Phase 5 milestone 5.0 spike for QUIC by name: a
// UDP relay that reads the server name from a client's QUIC Initial
// packets (RFC 9001 §5: keys derived from the destination connection id),
// holds the client's datagrams until it has the whole ClientHello, then
// forwards allowed names to the server untouched and drops the rest.
//
//	quicsni -run          relay + quic-go server + clients, prints results
//	quicsni -bench        cost of parsing one Initial
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

var saltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

func expandLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), n)
	if err != nil {
		panic(err)
	}
	return out
}

func varint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("short varint")
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, errors.New("short varint")
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n, nil
}

// crypto collects CRYPTO frame data from a client's Initial packets.
type cryptoStream struct {
	frags map[uint64][]byte
}

// initial decrypts the first (Initial) packet of a datagram and adds its
// CRYPTO frames. It does not modify pkt.
func (c *cryptoStream) initial(pkt []byte) (dcid []byte, err error) {
	if len(pkt) < 7 || pkt[0]&0x80 == 0 {
		return nil, errors.New("not a long header")
	}
	if v := binary.BigEndian.Uint32(pkt[1:5]); v != 1 {
		return nil, fmt.Errorf("QUIC version %#x", v)
	}
	if (pkt[0]&0x30)>>4 != 0 {
		return nil, errors.New("not an Initial")
	}
	p := 5
	dl := int(pkt[p])
	p++
	if p+dl > len(pkt) {
		return nil, errors.New("short")
	}
	dcid = pkt[p : p+dl]
	p += dl
	if p >= len(pkt) {
		return nil, errors.New("short")
	}
	sl := int(pkt[p])
	p += 1 + sl
	tl, n, err := varint(pkt[p:])
	if err != nil {
		return nil, err
	}
	p += n + int(tl)
	length, n, err := varint(pkt[p:])
	if err != nil {
		return nil, err
	}
	p += n
	pnOff := p
	if pnOff+int(length) > len(pkt) || pnOff+4+16 > len(pkt) {
		return nil, errors.New("short packet")
	}
	initSecret, _ := hkdf.Extract(sha256.New, dcid, saltV1)
	cs := expandLabel(initSecret, "client in", 32)
	key, iv, hp := expandLabel(cs, "quic key", 16), expandLabel(cs, "quic iv", 12), expandLabel(cs, "quic hp", 16)
	hb, _ := aes.NewCipher(hp)
	mask := make([]byte, 16)
	hb.Encrypt(mask, pkt[pnOff+4:pnOff+4+16])
	hdr := append([]byte(nil), pkt[:pnOff+4]...)
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&3) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOff+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[pnOff+i])
	}
	hdr = hdr[:pnOff+pnLen]
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}
	kb, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(kb)
	pl, err := aead.Open(nil, nonce, pkt[pnOff+pnLen:pnOff+int(length)], hdr)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	for len(pl) > 0 {
		switch t := pl[0]; {
		case t == 0x00 || t == 0x01: // PADDING, PING
			pl = pl[1:]
		case t == 0x06: // CRYPTO
			off, n1, err := varint(pl[1:])
			if err != nil {
				return nil, err
			}
			ln, n2, err := varint(pl[1+n1:])
			if err != nil {
				return nil, err
			}
			s := 1 + n1 + n2
			if s+int(ln) > len(pl) {
				return nil, errors.New("short CRYPTO")
			}
			if c.frags == nil {
				c.frags = map[uint64][]byte{}
			}
			c.frags[off] = append([]byte(nil), pl[s:s+int(ln)]...)
			pl = pl[s+int(ln):]
		case t == 0x02 || t == 0x03: // ACK: a client's first flight has none
			return nil, errors.New("ACK in client Initial")
		default:
			return nil, fmt.Errorf("frame %#x in Initial", t)
		}
	}
	return dcid, nil
}

// contiguous is the CRYPTO data from offset 0 as far as it is unbroken.
func (c *cryptoStream) contiguous() []byte {
	offs := make([]uint64, 0, len(c.frags))
	for o := range c.frags {
		offs = append(offs, o)
	}
	sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })
	var out []byte
	for _, o := range offs {
		if o > uint64(len(out)) {
			break
		}
		f := c.frags[o]
		if end := o + uint64(len(f)); end > uint64(len(out)) {
			out = append(out, f[uint64(len(out))-o:]...)
		}
	}
	return out
}

var errNeedMore = errors.New("ClientHello incomplete")

// sni parses a TLS ClientHello handshake message for server_name and
// whether it carries an ECH extension.
func sni(b []byte) (name string, ech bool, err error) {
	if len(b) < 4 {
		return "", false, errNeedMore
	}
	if b[0] != 1 {
		return "", false, errors.New("not a ClientHello")
	}
	l := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if len(b) < 4+l {
		return "", false, errNeedMore
	}
	h := b[4 : 4+l]
	p := 2 + 32
	if p >= len(h) {
		return "", false, errors.New("short")
	}
	p += 1 + int(h[p])
	if p+2 > len(h) {
		return "", false, errors.New("short")
	}
	p += 2 + int(binary.BigEndian.Uint16(h[p:]))
	if p >= len(h) {
		return "", false, errors.New("short")
	}
	p += 1 + int(h[p])
	if p+2 > len(h) {
		return "", false, errors.New("no extensions")
	}
	end := p + 2 + int(binary.BigEndian.Uint16(h[p:]))
	p += 2
	for p+4 <= end && end <= len(h) {
		t, el := binary.BigEndian.Uint16(h[p:]), int(binary.BigEndian.Uint16(h[p+2:]))
		e := h[p+4 : p+4+el]
		switch t {
		case 0:
			if len(e) >= 5 && e[2] == 0 {
				nl := int(binary.BigEndian.Uint16(e[3:]))
				if 5+nl <= len(e) {
					name = string(e[5 : 5+nl])
				}
			}
		case 0xfe0d:
			ech = true
		}
		p += 4 + el
	}
	return name, ech, nil
}

// ---- relay ----

type flow struct {
	cs      cryptoStream
	held    [][]byte
	up      *net.UDPConn
	decided bool
	allowed bool
	name    string
	packets int
	took    time.Duration
}

type relay struct {
	ln      *net.UDPConn
	backend *net.UDPAddr
	allow   map[string]bool
	mu      sync.Mutex
	flows   map[string]*flow
	results chan string
}

func (r *relay) serve() {
	buf := make([]byte, 65536)
	for {
		n, src, err := r.ln.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		r.mu.Lock()
		f := r.flows[src.String()]
		if f == nil {
			f = &flow{}
			r.flows[src.String()] = f
		}
		r.mu.Unlock()
		if f.decided {
			if f.allowed {
				f.up.Write(pkt)
			}
			continue
		}
		t := time.Now()
		f.packets++
		f.held = append(f.held, pkt)
		if _, err := f.cs.initial(pkt); err != nil {
			f.decided = true
			r.results <- fmt.Sprintf("%s: refused, unparseable: %v", src, err)
			continue
		}
		name, ech, err := sni(f.cs.contiguous())
		f.took += time.Since(t)
		if errors.Is(err, errNeedMore) {
			if f.packets > 8 {
				f.decided = true
				r.results <- fmt.Sprintf("%s: refused, ClientHello not complete in 8 datagrams", src)
			}
			continue
		}
		f.decided, f.name = true, name
		f.allowed = err == nil && r.allow[name]
		r.results <- fmt.Sprintf("%s: sni=%q ech=%v datagrams=%d parse=%v allowed=%v", src, name, ech, f.packets, f.took, f.allowed)
		if !f.allowed {
			continue
		}
		up, err := net.DialUDP("udp", nil, r.backend)
		if err != nil {
			log.Fatal(err)
		}
		f.up = up
		for _, h := range f.held {
			up.Write(h)
		}
		go func(src *net.UDPAddr) {
			b := make([]byte, 65536)
			for {
				n, err := up.Read(b)
				if err != nil {
					return
				}
				r.ln.WriteToUDP(b[:n], src)
			}
		}(src)
	}
}

func selfSigned() tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"allowed.test", "denied.test"}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func backend() *net.UDPAddr {
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSigned()}, NextProtos: []string{"spike"}}, nil)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				s, err := c.AcceptStream(context.Background())
				if err != nil {
					return
				}
				io.Copy(s, s)
				s.Close()
			}()
		}
	}()
	return ln.Addr().(*net.UDPAddr)
}

func dial(addr, name string, curves []tls.CurveID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := quic.DialAddr(ctx, addr, &tls.Config{ServerName: name, InsecureSkipVerify: true, NextProtos: []string{"spike"},
		CurvePreferences: curves}, nil)
	if err != nil {
		return err
	}
	defer c.CloseWithError(0, "")
	s, err := c.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	s.Write([]byte("ping"))
	s.Close()
	b, err := io.ReadAll(s)
	if err != nil {
		return err
	}
	if string(b) != "ping" {
		return fmt.Errorf("echo %q", b)
	}
	return nil
}

func main() {
	run := flag.Bool("run", false, "")
	bench := flag.Bool("bench", false, "")
	flag.Parse()
	be := backend()
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		log.Fatal(err)
	}
	r := &relay{ln: ln, backend: be, allow: map[string]bool{"allowed.test": true}, flows: map[string]*flow{}, results: make(chan string, 64)}
	if *bench {
		// Capture one Initial from a client, then time parsing it.
		var first []byte
		go func() {
			b := make([]byte, 65536)
			n, _, _ := ln.ReadFromUDP(b)
			first = append([]byte(nil), b[:n]...)
			ln.Close()
		}()
		dial(ln.LocalAddr().String(), "allowed.test", []tls.CurveID{tls.X25519})
		time.Sleep(100 * time.Millisecond)
		const N = 20000
		t := time.Now()
		for i := 0; i < N; i++ {
			var cs cryptoStream
			if _, err := cs.initial(first); err != nil {
				log.Fatal(err)
			}
			if _, _, err := sni(cs.contiguous()); err != nil {
				log.Fatal(err)
			}
		}
		fmt.Printf("parse one Initial (%d bytes): %v\n", len(first), time.Since(t)/N)
		return
	}
	if !*run {
		flag.Usage()
		return
	}
	go r.serve()
	go func() {
		for s := range r.results {
			fmt.Println("relay:", s)
		}
	}()
	addr := ln.LocalAddr().String()
	for _, tc := range []struct {
		name   string
		curves []tls.CurveID
		label  string
	}{
		{"allowed.test", nil, "default key shares (X25519MLKEM768)"},
		{"allowed.test", []tls.CurveID{tls.X25519}, "X25519 only"},
		{"denied.test", nil, "default key shares"},
	} {
		err := dial(addr, tc.name, tc.curves)
		time.Sleep(50 * time.Millisecond)
		fmt.Printf("client %s, %s: err=%v\n", tc.name, tc.label, err)
	}
	time.Sleep(100 * time.Millisecond)
}
