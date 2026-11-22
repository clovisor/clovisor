// Command resolver is the spike's forced local resolver. It answers UDP and
// TCP queries on one port, identifies the run behind each query by socket
// diagnostics, answers NXDOMAIN for names outside -allow, forwards the rest
// upstream, and strips the ech parameter from HTTPS and SVCB answers.
// Not production code.
package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/clovisor/clovisor/spikes/phase3/sockdiag"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

var (
	listen   = flag.String("listen", "127.0.0.1:15053", "address, UDP and TCP")
	upstream = flag.String("upstream", "127.0.0.53:53", "resolver to forward allowed names to")
	allow    = flag.String("allow", "example.com", "comma-separated names; each also allows its subdomains")
)

func main() {
	flag.Parse()
	pc, err := net.ListenPacket("udp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				log.Fatal(err)
			}
			go serveTCP(c)
		}
	}()
	local := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			log.Fatal(err)
		}
		peer := from.(*net.UDPAddr).AddrPort()
		// UDP socket diagnostics find the socket that would receive a
		// datagram from the first address to the second (udp_dump_one), so
		// the client's socket is found with us first and the client second.
		// That matches connected (glibc, dig) and unconnected clients alike.
		cg, err := sockdiag.Lookup(unix.IPPROTO_UDP, local, peer)
		resp := answer(buf[:n], "udp", peer, cg, err)
		if resp != nil {
			pc.WriteTo(resp, from)
		}
	}
}

func serveTCP(c net.Conn) {
	defer c.Close()
	peer := c.RemoteAddr().(*net.TCPAddr).AddrPort()
	local := c.LocalAddr().(*net.TCPAddr).AddrPort()
	cg, cerr := sockdiag.CgroupOf(peer, local)
	for {
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		resp := answer(q, "tcp", peer, cg, cerr)
		if resp == nil {
			return
		}
		binary.BigEndian.PutUint16(l[:], uint16(len(resp)))
		c.Write(append(l[:], resp...))
	}
}

func allowed(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for _, a := range strings.Split(*allow, ",") {
		if name == a || strings.HasSuffix(name, "."+a) {
			return true
		}
	}
	return false
}

func answer(q []byte, proto string, peer netip.AddrPort, cg uint64, cerr error) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		return nil
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 {
		return nil
	}
	name := qs[0].Name.String()
	if !allowed(name) {
		log.Printf("%s %s cgroup=%d (%v) %s %s: NXDOMAIN", proto, peer, cg, cerr, qs[0].Type, name)
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true, RCode: dnsmessage.RCodeNameError})
		b.StartQuestions()
		b.Question(qs[0])
		out, _ := b.Finish()
		return out
	}
	resp, err := forward(q)
	if err != nil {
		log.Printf("%s %s %s: upstream: %v", proto, peer, name, err)
		return nil
	}
	resp, stripped := stripECH(resp)
	log.Printf("%s %s cgroup=%d (%v) %s %s: forwarded, ech stripped from %d records", proto, peer, cg, cerr, qs[0].Type, name, stripped)
	return resp
}

func forward(q []byte) ([]byte, error) {
	c, err := net.DialTimeout("udp", *upstream, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	return buf[:n], err
}

// stripECH rebuilds the message without the ech SvcParam (key 5) in any
// HTTPS or SVCB record. Clients then fall back to a cleartext SNI, which
// the transparent listener can read.
func stripECH(m []byte) ([]byte, int) {
	var msg dnsmessage.Message
	if err := msg.Unpack(m); err != nil {
		return m, 0
	}
	n := 0
	for _, sec := range [][]dnsmessage.Resource{msg.Answers, msg.Additionals} {
		for i := range sec {
			switch b := sec[i].Body.(type) {
			case *dnsmessage.HTTPSResource:
				if _, ok := b.GetParam(dnsmessage.SVCParamECH); ok {
					b.DeleteParam(dnsmessage.SVCParamECH)
					n++
				}
			case *dnsmessage.SVCBResource:
				if _, ok := b.GetParam(dnsmessage.SVCParamECH); ok {
					b.DeleteParam(dnsmessage.SVCParamECH)
					n++
				}
			}
		}
	}
	if n == 0 {
		return m, 0
	}
	out, err := msg.Pack()
	if err != nil {
		return m, 0
	}
	return out, n
}
