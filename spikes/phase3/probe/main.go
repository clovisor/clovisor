// Command probe stands in for the transparent listener. For each accepted
// connection it asks the kernel for SO_ORIGINAL_DST (answered by the
// spike's cgroup/getsockopt program), looks up the client's cgroup by
// socket diagnostics, prints both, writes them back to the client and
// closes. Not production code.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"github.com/clovisor/clovisor/spikes/phase3/sockdiag"
	"golang.org/x/sys/unix"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:15001", "address")
	flag.Parse()
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handle(c.(*net.TCPConn))
	}
}

func handle(c *net.TCPConn) {
	defer c.Close()
	local := c.LocalAddr().(*net.TCPAddr).AddrPort()
	remote := c.RemoteAddr().(*net.TCPAddr).AddrPort()
	orig, oerr := originalDst(c, local.Addr().Is4())
	cg, cerr := sockdiag.CgroupOf(remote, local)
	line := fmt.Sprintf("client=%s orig=%s (%v) cgroup=%d (%v)", remote, orig, oerr, cg, cerr)
	log.Print(line)
	fmt.Fprintln(c, line)
}

func originalDst(c *net.TCPConn, v4 bool) (netip.AddrPort, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var out netip.AddrPort
	var serr error
	raw.Control(func(fd uintptr) {
		var buf [128]byte
		l := uint32(len(buf))
		level := unix.SOL_IP
		if !v4 {
			level = unix.SOL_IPV6
		}
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, uintptr(level), 80,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&l)), 0)
		if e != 0 {
			serr = e
			return
		}
		port := binary.BigEndian.Uint16(buf[2:])
		switch binary.LittleEndian.Uint16(buf[0:]) {
		case unix.AF_INET:
			out = netip.AddrPortFrom(netip.AddrFrom4([4]byte(buf[4:8])), port)
		case unix.AF_INET6:
			out = netip.AddrPortFrom(netip.AddrFrom16([16]byte(buf[8:24])), port)
		default:
			serr = fmt.Errorf("family %d", binary.LittleEndian.Uint16(buf[0:]))
		}
	})
	return out, serr
}
