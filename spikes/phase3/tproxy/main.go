// Command tproxy loads the Phase 3 spike BPF program (bpf/transparent.o),
// attaches it, writes a heartbeat once a second, and prints each verdict.
// SIGUSR1 stops the heartbeat, to show the hooks failing closed; SIGUSR2
// restarts it. Not production code.
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

type config struct {
	AgentsCgroupID uint64
	AgentsLevel    uint32
	Mode           uint32
	HeartbeatNs    uint64
	StaleNs        uint64
	ProxyPort      uint16
	DNSPort        uint16
	ExplicitPort   uint16
	_              uint16
}

var verdictNames = map[uint32]string{
	1: "redirect", 2: "deny-unhealthy", 3: "deny-udp", 4: "same-run",
	5: "exception", 6: "dns", 7: "audit-redirect", 8: "audit-deny",
}

func main() {
	obj := flag.String("obj", "bpf/transparent.o", "BPF object")
	agents := flag.String("agents", "/sys/fs/cgroup/agents", "agents cgroup")
	proxyCg := flag.String("proxy-cgroup", "/sys/fs/cgroup", "cgroup of the proxy, for cgroup/getsockopt")
	mode := flag.String("mode", "enforce", "audit or enforce")
	proxyPort := flag.Uint("proxy-port", 15001, "transparent listener port")
	dnsPort := flag.Uint("dns-port", 15053, "local resolver port")
	explicitPort := flag.Uint("explicit-port", 18000, "explicit proxy port (exception)")
	stale := flag.Duration("stale", 3*time.Second, "heartbeat age that counts as unhealthy")
	flag.Parse()

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

	var st unix.Stat_t
	if err := unix.Stat(*agents, &st); err != nil {
		log.Fatal(err)
	}
	rel := strings.Trim(strings.TrimPrefix(filepath.Clean(*agents), "/sys/fs/cgroup"), "/")
	c := config{
		AgentsCgroupID: st.Ino,
		AgentsLevel:    uint32(len(strings.Split(rel, "/"))),
		Mode:           map[string]uint32{"audit": 1, "enforce": 2}[*mode],
		StaleNs:        uint64(stale.Nanoseconds()),
		ProxyPort:      uint16(*proxyPort),
		DNSPort:        uint16(*dnsPort),
		ExplicitPort:   uint16(*explicitPort),
	}
	if c.Mode == 0 {
		log.Fatalf("mode %q", *mode)
	}
	cfgMap := coll.Maps["config"]
	beat := func(on bool) {
		c.HeartbeatNs = 0
		if on {
			var ts unix.Timespec
			unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
			c.HeartbeatNs = uint64(ts.Nano())
		}
		if err := cfgMap.Put(uint32(0), c); err != nil {
			log.Fatal(err)
		}
	}
	beat(true)

	attach := []struct {
		prog, cg string
		typ      ebpf.AttachType
	}{
		{"t_connect4", *agents, ebpf.AttachCGroupInet4Connect},
		{"t_connect6", *agents, ebpf.AttachCGroupInet6Connect},
		{"t_sendmsg4", *agents, ebpf.AttachCGroupUDP4Sendmsg},
		{"t_sendmsg6", *agents, ebpf.AttachCGroupUDP6Sendmsg},
		{"t_recvmsg4", *agents, ebpf.AttachCGroupUDP4Recvmsg},
		{"t_recvmsg6", *agents, ebpf.AttachCGroupUDP6Recvmsg},
		{"t_getpeername4", *agents, ebpf.AttachCgroupInet4GetPeername},
		{"t_getpeername6", *agents, ebpf.AttachCgroupInet6GetPeername},
		{"t_bind4", *agents, ebpf.AttachCGroupInet4Bind},
		{"t_bind6", *agents, ebpf.AttachCGroupInet6Bind},
		{"t_sockops", *agents, ebpf.AttachCGroupSockOps},
		{"t_getsockopt", *proxyCg, ebpf.AttachCGroupGetsockopt},
	}
	for _, a := range attach {
		l, err := link.AttachCgroup(link.CgroupOptions{Path: a.cg, Attach: a.typ, Program: coll.Programs[a.prog]})
		if err != nil {
			log.Fatalf("attach %s to %s: %v", a.prog, a.cg, err)
		}
		defer l.Close()
	}
	log.Printf("attached: mode=%s agents=%s (id %d, level %d) proxy=:%d dns=:%d explicit=:%d",
		*mode, *agents, c.AgentsCgroupID, c.AgentsLevel, c.ProxyPort, c.DNSPort, c.ExplicitPort)

	var alive atomic.Bool
	alive.Store(true)
	go func() {
		for range time.Tick(time.Second) {
			beat(alive.Load())
		}
	}()

	rd, err := ringbuf.NewReader(coll.Maps["verdicts"])
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			r, err := rd.Read()
			if err != nil {
				return
			}
			b := r.RawSample
			run := binary.LittleEndian.Uint64(b[0:])
			v := binary.LittleEndian.Uint32(b[8:])
			port := binary.BigEndian.Uint16(b[12:])
			typ := binary.LittleEndian.Uint16(b[14:])
			ip := netip.AddrFrom16([16]byte(b[16:32])).Unmap()
			proto := map[uint16]string{1: "tcp", 2: "udp"}[typ]
			fmt.Printf("verdict run=%d %s %s %s\n", run, proto, netip.AddrPortFrom(ip, port), verdictNames[v])
		}
	}()

	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2)
	for s := range sig {
		switch s {
		case syscall.SIGUSR1:
			alive.Store(false)
			beat(false)
			log.Print("heartbeat stopped")
		case syscall.SIGUSR2:
			alive.Store(true)
			beat(true)
			log.Print("heartbeat restarted")
		default:
			rd.Close()
			return
		}
	}
}
