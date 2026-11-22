// Package sockdiag looks up the cgroup of a TCP or UDP socket by its
// 4-tuple via NETLINK_SOCK_DIAG (INET_DIAG_CGROUP_ID, Linux 5.7+).
//
// Copied from the Phase 2 spike, with the protocol as a parameter, to ask
// whether the forced resolver can identify the run behind a UDP query.
package sockdiag

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	sockDiagByFamily = 20
	inetDiagCgroupID = 21
	inetDiagNoCookie = ^uint32(0)
)

// ErrNotFound means no socket has that 4-tuple.
var ErrNotFound = errors.New("socket not found")

// CgroupOf returns the cgroup id of the TCP socket bound to local and
// connected to remote (as seen from the socket's own side).
func CgroupOf(local, remote netip.AddrPort) (uint64, error) {
	return Lookup(unix.IPPROTO_TCP, local, remote)
}

// Lookup is CgroupOf for protocol proto (IPPROTO_TCP or IPPROTO_UDP). For
// UDP the kernel returns the socket that would receive a datagram from local
// to remote, so pass the server's address as local and the client's as
// remote to find the client's socket, connected or not.
func Lookup(proto byte, local, remote netip.AddrPort) (uint64, error) {
	if local.Addr().Is4() != remote.Addr().Is4() {
		return 0, fmt.Errorf("mixed address families")
	}
	family := byte(unix.AF_INET6)
	if local.Addr().Is4() {
		family = unix.AF_INET
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, err
	}

	// nlmsghdr (16) + inet_diag_req_v2 (56)
	req := make([]byte, 16+56)
	le := binary.LittleEndian
	le.PutUint32(req[0:], uint32(len(req)))
	le.PutUint16(req[4:], sockDiagByFamily)
	le.PutUint16(req[6:], unix.NLM_F_REQUEST)
	le.PutUint32(req[8:], 1) // seq
	b := req[16:]
	b[0] = family
	b[1] = proto
	b[2] = 0                        // idiag_ext
	le.PutUint32(b[4:], 0xffffffff) // all states
	id := b[8:]                     // inet_diag_sockid
	binary.BigEndian.PutUint16(id[0:], local.Port())
	binary.BigEndian.PutUint16(id[2:], remote.Port())
	putAddr(id[4:20], local.Addr())
	putAddr(id[20:36], remote.Addr())
	le.PutUint32(id[40:], inetDiagNoCookie)
	le.PutUint32(id[44:], inetDiagNoCookie)

	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, err
	}
	buf := make([]byte, 8192)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return 0, err
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return 0, err
	}
	for _, m := range msgs {
		switch m.Header.Type {
		case unix.NLMSG_ERROR:
			if len(m.Data) >= 4 {
				if e := int32(le.Uint32(m.Data)); e != 0 {
					if unix.Errno(-e) == unix.ENOENT {
						return 0, ErrNotFound
					}
					return 0, unix.Errno(-e)
				}
			}
		case sockDiagByFamily:
			const msgLen = 72 // inet_diag_msg
			if len(m.Data) < msgLen {
				return 0, fmt.Errorf("short inet_diag_msg")
			}
			for a := m.Data[msgLen:]; len(a) >= 4; {
				l := int(le.Uint16(a[0:]))
				t := le.Uint16(a[2:])
				if l < 4 || l > len(a) {
					break
				}
				if t == inetDiagCgroupID && l >= 12 {
					return le.Uint64(a[4:12]), nil
				}
				a = a[(l+3)&^3:]
			}
			return 0, fmt.Errorf("no INET_DIAG_CGROUP_ID attribute (kernel < 5.7?)")
		}
	}
	return 0, ErrNotFound
}

func putAddr(dst []byte, a netip.Addr) {
	if a.Is4() {
		v := a.As4()
		copy(dst[0:4], v[:])
		return
	}
	v := a.As16()
	copy(dst, v[:])
}
