// Command lsmspike loads the Phase 4 spike (bpf/lsm.o), attaching each
// program on its own so one the kernel refuses does not hide the others,
// and prints what the hooks see. SIGUSR1 prints the per-cgroup hook
// counters. Not production code.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

type config struct {
	AgentsID    uint64
	AgentsLevel uint32
	Enforce     uint32
}

type event struct {
	Type   uint32
	Ret    int32
	Run    uint64
	Other  uint64
	Flags  uint32
	Depth  uint32
	Path   [256]byte
	Interp [64]byte
}

var progRE = regexp.MustCompile(`program (\w+)`)

func main() {
	obj := flag.String("obj", "bpf/lsm.o", "BPF object")
	agents := flag.String("agents", "/sys/fs/cgroup/spike4", "agents cgroup (created)")
	enforce := flag.Bool("enforce", false, "refuse untrusted execs, raw sockets and foreign sockets")
	noIMA := flag.Bool("no-ima", false, "do not attach the IMA hashing program (to measure its cost)")
	flag.Parse()

	if err := os.MkdirAll(*agents, 0o755); err != nil {
		log.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(*agents, &st); err != nil {
		log.Fatal(err)
	}
	rel := strings.Trim(strings.TrimPrefix(filepath.Clean(*agents), "/sys/fs/cgroup"), "/")

	spec, err := ebpf.LoadCollectionSpec(*obj)
	if err != nil {
		log.Fatal(err)
	}
	// Load, dropping each program the verifier refuses, so the rest load.
	var coll *ebpf.Collection
	for {
		coll, err = ebpf.NewCollection(spec)
		if err == nil {
			break
		}
		m := progRE.FindStringSubmatch(err.Error())
		if m == nil || spec.Programs[m[1]] == nil {
			log.Fatalf("load: %v", err)
		}
		var ve *ebpf.VerifierError
		msg := err.Error()
		if errors.As(err, &ve) && len(ve.Log) > 0 {
			msg = strings.Join(ve.Log[max(0, len(ve.Log)-3):], " | ")
		}
		fmt.Printf("REFUSED %-24s %s\n", m[1], msg)
		delete(spec.Programs, m[1])
	}
	defer coll.Close()
	c := config{AgentsID: st.Ino, AgentsLevel: uint32(len(strings.Split(rel, "/")))}
	if *enforce {
		c.Enforce = 1
	}
	if err := coll.Maps["spike_cfg"].Put(uint32(0), c); err != nil {
		log.Fatal(err)
	}

	names := make([]string, 0, len(coll.Programs))
	for n := range coll.Programs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := coll.Programs[n]
		if *noIMA && n == "exec_ima" {
			continue
		}
		var l link.Link
		var err error
		kind := "lsm"
		if strings.HasPrefix(n, "cg_") {
			kind = "lsm_cgroup"
			l, err = link.AttachCgroup(link.CgroupOptions{Path: *agents, Attach: ebpf.AttachLSMCgroup, Program: p})
		} else if n == "unix_connect_hook" {
			kind = "cgroup/connect_unix"
			l, err = link.AttachCgroup(link.CgroupOptions{Path: *agents, Attach: ebpf.AttachCgroupUnixConnect, Program: p})
		} else {
			l, err = link.AttachLSM(link.LSMOptions{Program: p})
		}
		if err != nil {
			fmt.Printf("ATTACH FAILED %-18s %s: %v\n", n, kind, err)
			continue
		}
		defer l.Close()
		fmt.Printf("attached %-24s %s\n", n, kind)
	}
	log.Printf("ready: agents %s (id %d, level %d), enforce=%v", *agents, c.AgentsID, c.AgentsLevel, *enforce)

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			r, err := rd.Read()
			if err != nil {
				return
			}
			var e event
			binary.Read(bytes.NewReader(r.RawSample), binary.LittleEndian, &e)
			print(e)
		}
	}()

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)
	for s := range sig {
		counts := []string{}
		for i, h := range []string{"socket_create", "socket_connect", "socket_sendmsg", "unix_stream_connect", "bprm_check_security"} {
			var n uint64
			coll.Maps["cg_calls"].Lookup(uint32(i), &n)
			counts = append(counts, fmt.Sprintf("%s=%d", h, n))
		}
		fmt.Printf("lsm_cgroup calls: %s\n", strings.Join(counts, " "))
		if s != syscall.SIGUSR1 {
			rd.Close()
			return
		}
	}
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func print(e event) {
	switch e.Type {
	case 1:
		var fl []string
		for bit, n := range map[uint32]string{1: "root-owned", 2: "not-writable", 4: "path-trusted", 8: "ro-sb", 16: "ro-mnt", 32: "walk-done"} {
			if e.Flags&bit != 0 {
				fl = append(fl, n)
			}
		}
		sort.Strings(fl)
		fmt.Printf("exec     run=%d d_path=%d %q interp=%q depth=%d [%s]\n", e.Run, e.Ret, cstr(e.Path[:]), cstr(e.Interp[:]), e.Depth, strings.Join(fl, " "))
	case 2:
		fmt.Printf("ima      run=%d ret=%d hash=%x\n", e.Run, e.Ret, e.Path[:32])
	case 3:
		fmt.Printf("create   run=%d family=%d type=%d -> %d\n", e.Run, e.Other, e.Flags, e.Ret)
	case 4:
		name := cstr(e.Path[:])
		if e.Flags&1 != 0 {
			name = "@" + cstr(e.Path[1:])
		}
		hook := "lsm/socket_connect"
		if e.Flags&4 != 0 {
			hook = "cgroup/connect_unix"
		}
		fmt.Printf("unix     run=%d %s %q addrlen=%d\n", e.Run, hook, name, e.Depth)
	case 5:
		kind := "stream"
		if e.Flags&2 != 0 {
			kind = "dgram"
		}
		fmt.Printf("unixpeer run=%d %s peer-cgroup=%d same-run=%v\n", e.Run, kind, e.Other, e.Flags&1 != 0)
	case 6:
		op := "connect"
		if e.Flags == 1 {
			op = "sendmsg"
		}
		fmt.Printf("foreign  run=%d %s on a socket from cgroup %d -> %d\n", e.Run, op, e.Other, e.Ret)
	}
}
