// Copyright (c) Authors of Clovisor
//
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Apache License, Version 2.0
// which accompanies this distribution, and is available at
// http://www.apache.org/licenses/LICENSE-2.0

package clovisor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// QUIC Initial packets (milestone 5.6, RFC 9000 §17.2.2, RFC 9001 §5).
// Initial packets are protected with keys derived from the client's
// destination connection id, which is on the wire, so anyone can read
// them: the relay reads the ClientHello's server name from them, as the
// proxy reads SNI from TLS over TCP. Only QUIC version 1 is read;
// anything else is refused, and the client falls back to TCP.

var quicSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

// hkdfExtract and hkdfExpand are RFC 5869 with SHA-256.
func hkdfExtract(salt, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

func hkdfExpand(prk, info []byte, n int) []byte {
	var out, t []byte
	for i := byte(1); len(out) < n; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{i})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

// expandLabel is TLS 1.3's HKDF-Expand-Label with an empty context.
func expandLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := binary.BigEndian.AppendUint16(nil, uint16(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	return hkdfExpand(secret, info, n)
}

// initialKeys are one direction's Initial packet protection.
type initialKeys struct {
	aead cipher.AEAD
	iv   []byte
	hp   cipher.Block
}

func newInitialKeys(dcid []byte, label string) initialKeys {
	secret := expandLabel(hkdfExtract(quicSaltV1, dcid), label, 32)
	kb, _ := aes.NewCipher(expandLabel(secret, "quic key", 16))
	aead, _ := cipher.NewGCM(kb)
	hp, _ := aes.NewCipher(expandLabel(secret, "quic hp", 16))
	return initialKeys{aead: aead, iv: expandLabel(secret, "quic iv", 12), hp: hp}
}

func (k initialKeys) nonce(pn uint64) []byte {
	n := append([]byte(nil), k.iv...)
	for i := 0; i < 8; i++ {
		n[11-i] ^= byte(pn >> (8 * i))
	}
	return n
}

func quicVarint(b []byte) (uint64, int, error) {
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

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v < 1<<30:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	}
	return append(b, byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// clientHello collects the CRYPTO data of a client's Initial packets.
type clientHello struct {
	dcid, scid []byte
	frags      map[uint64][]byte
	size       int
}

// maxCryptoData bounds what is collected: a ClientHello with post-quantum
// key shares is about 1.8 KB.
const maxCryptoData = 16 << 10

// add decrypts the Initial packets of one client datagram (coalesced
// packets included) and keeps their CRYPTO frames. A datagram whose first
// packet is not a version 1 Initial is an error.
func (c *clientHello) add(dgram []byte) error {
	first := true
	for len(dgram) > 0 {
		if dgram[0]&0x80 == 0 {
			if first {
				return errors.New("not a long header packet")
			}
			return nil // a short header packet coalesced after: not ours to read
		}
		n, err := c.packet(dgram, first)
		if err != nil {
			return err
		}
		dgram, first = dgram[n:], false
	}
	return nil
}

// packet reads one long header packet and returns its length.
func (c *clientHello) packet(pkt []byte, first bool) (int, error) {
	if len(pkt) < 7 {
		return 0, errors.New("short packet")
	}
	if v := binary.BigEndian.Uint32(pkt[1:5]); v != 1 {
		return 0, fmt.Errorf("QUIC version %#x", v)
	}
	p := 5
	dl := int(pkt[p])
	p++
	if dl > 20 || p+dl >= len(pkt) {
		return 0, errors.New("bad destination connection id")
	}
	dcid := pkt[p : p+dl]
	p += dl
	sl := int(pkt[p])
	p++
	if sl > 20 || p+sl > len(pkt) {
		return 0, errors.New("bad source connection id")
	}
	scid := pkt[p : p+sl]
	p += sl
	typ := (pkt[0] & 0x30) >> 4
	if typ == 0 {
		tl, n, err := quicVarint(pkt[p:])
		if err != nil {
			return 0, err
		}
		p += n + int(tl)
	}
	length, n, err := quicVarint(pkt[p:])
	if err != nil {
		return 0, err
	}
	p += n
	end := p + int(length)
	if end > len(pkt) || length < 20 {
		return 0, errors.New("short packet")
	}
	if typ != 0 {
		if first {
			return 0, errors.New("not an Initial packet")
		}
		return end, nil // 0-RTT or Handshake coalesced after: skipped
	}
	if c.dcid == nil {
		c.dcid, c.scid = append([]byte(nil), dcid...), append([]byte(nil), scid...)
	} else if string(dcid) != string(c.dcid) {
		return 0, errors.New("destination connection id changed")
	}
	k := newInitialKeys(c.dcid, "client in")
	mask := make([]byte, 16)
	if p+4+16 > len(pkt) {
		return 0, errors.New("short packet")
	}
	k.hp.Encrypt(mask, pkt[p+4:p+4+16])
	hdr := append([]byte(nil), pkt[:p+4]...)
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&3) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[p+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[p+i])
	}
	hdr = hdr[:p+pnLen]
	pl, err := k.aead.Open(nil, k.nonce(pn), pkt[p+pnLen:end], hdr)
	if err != nil {
		return 0, errors.New("Initial packet does not decrypt")
	}
	return end, c.frames(pl)
}

func (c *clientHello) frames(pl []byte) error {
	for len(pl) > 0 {
		switch t := pl[0]; {
		case t == 0x00 || t == 0x01: // PADDING, PING
			pl = pl[1:]
		case t == 0x06: // CRYPTO
			off, n1, err := quicVarint(pl[1:])
			if err != nil {
				return err
			}
			ln, n2, err := quicVarint(pl[1+n1:])
			if err != nil {
				return err
			}
			s := 1 + n1 + n2
			if s+int(ln) > len(pl) || off+ln > maxCryptoData {
				return errors.New("bad CRYPTO frame")
			}
			if c.frags == nil {
				c.frags = map[uint64][]byte{}
			}
			if _, dup := c.frags[off]; !dup {
				c.size += int(ln)
				if c.size > maxCryptoData {
					return errors.New("too much CRYPTO data")
				}
				c.frags[off] = append([]byte(nil), pl[s:s+int(ln)]...)
			}
			pl = pl[s+int(ln):]
		case t == 0x02 || t == 0x03: // ACK: a client's first flight has none
			return errors.New("ACK in a client's first Initial")
		case t == 0x1c: // CONNECTION_CLOSE
			return errors.New("client closed the connection")
		default:
			return fmt.Errorf("frame %#x in a client Initial", t)
		}
	}
	return nil
}

func (c *clientHello) contiguous() []byte {
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
		if f := c.frags[o]; o+uint64(len(f)) > uint64(len(out)) {
			out = append(out, f[uint64(len(out))-o:]...)
		}
	}
	return out
}

var errHelloIncomplete = errors.New("ClientHello incomplete")

// helloServerName reads server_name, and whether there is an ECH
// extension, from a TLS ClientHello handshake message.
func helloServerName(b []byte) (name string, ech bool, err error) {
	if len(b) < 4 {
		return "", false, errHelloIncomplete
	}
	if b[0] != 1 {
		return "", false, errors.New("not a ClientHello")
	}
	l := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if len(b) < 4+l {
		return "", false, errHelloIncomplete
	}
	h := b[4 : 4+l]
	bad := errors.New("malformed ClientHello")
	p := 2 + 32 // version, random
	if p >= len(h) {
		return "", false, bad
	}
	p += 1 + int(h[p]) // session id
	if p+2 > len(h) {
		return "", false, bad
	}
	p += 2 + int(binary.BigEndian.Uint16(h[p:])) // cipher suites
	if p >= len(h) {
		return "", false, bad
	}
	p += 1 + int(h[p]) // compression methods
	if p+2 > len(h) {
		return "", false, bad
	}
	end := p + 2 + int(binary.BigEndian.Uint16(h[p:]))
	p += 2
	if end > len(h) {
		return "", false, bad
	}
	for p+4 <= end {
		t, el := binary.BigEndian.Uint16(h[p:]), int(binary.BigEndian.Uint16(h[p+2:]))
		if p+4+el > end {
			return "", false, bad
		}
		e := h[p+4 : p+4+el]
		switch t {
		case 0: // server_name: a list holding one host_name
			if len(e) < 5 || e[2] != 0 {
				return "", false, bad
			}
			nl := int(binary.BigEndian.Uint16(e[3:]))
			if 5+nl > len(e) {
				return "", false, bad
			}
			if name != "" {
				return "", false, errors.New("two server names")
			}
			name = string(e[5 : 5+nl])
		case 0xfe0d: // encrypted_client_hello
			ech = true
		}
		p += 4 + el
	}
	return name, ech, nil
}

// serverClose is a server Initial packet closing the connection with
// CONNECTION_REFUSED and a reason (RFC 9000 §10.2.3): what a client is
// told when the relay refuses it, so it can report why and fall back.
func serverClose(c *clientHello, reason string) []byte {
	if len(reason) > 512 {
		reason = reason[:512]
	}
	// CONNECTION_CLOSE (transport): code, frame type, reason.
	frame := []byte{0x1c}
	frame = appendVarint(frame, 0x02) // CONNECTION_REFUSED
	frame = appendVarint(frame, 0)
	frame = appendVarint(frame, uint64(len(reason)))
	frame = append(frame, reason...)
	scid := make([]byte, 8)
	rand.Read(scid)
	// The client's source id is our destination.
	return sealInitial(newInitialKeys(c.dcid, "server in"), c.scid, scid, frame)
}

// sealInitial builds a protected Initial packet, packet number 0, with no
// token.
func sealInitial(k initialKeys, dcid, scid, payload []byte) []byte {
	const pn, pnLen = 0, 2
	hdr := []byte{0xc0 | (pnLen - 1), 0, 0, 0, 1}
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = appendVarint(hdr, 0) // no token
	// The header protection sample starts 4 bytes after the packet
	// number: the payload is padded to reach it.
	frame := append([]byte(nil), payload...)
	for len(frame) < 4 {
		frame = append(frame, 0)
	}
	length := pnLen + len(frame) + k.aead.Overhead()
	hdr = append(hdr, byte(0x40|length>>8), byte(length)) // a 2-byte varint
	pnOff := len(hdr)
	hdr = append(hdr, 0, byte(pn))
	sealed := k.aead.Seal(nil, k.nonce(pn), frame, hdr)
	pkt := append(hdr, sealed...)
	mask := make([]byte, 16)
	k.hp.Encrypt(mask, pkt[pnOff+4:pnOff+4+16])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		pkt[pnOff+i] ^= mask[1+i]
	}
	return pkt
}
