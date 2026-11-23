// Command hashcache loads bpf/hashcache.o and prints one line per exec
// under /sys/fs/cgroup/spike5: whether the BPF hash cache would have
// answered, whether that answer was stale, and the cost of each path.
// Not production code.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
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
	Pad         uint32
}

type event struct {
	Ino       uint64
	Version   uint64
	CtimeSec  int64
	CtimeNsec uint32
	Gen       uint32
	LookupNs  uint32
	HashNs    uint32
	Ret       int32
	Hit       uint8
	Stale     uint8
	SBIVer    uint8
	Pad       uint8
	Magic     uint32
	Hash      [8]byte
}

func main() {
	obj := flag.String("obj", "bpf/hashcache.o", "")
	cg := flag.String("cgroup", "/sys/fs/cgroup/spike5", "created")
	flag.Parse()
	if err := os.MkdirAll(*cg, 0o755); err != nil {
		log.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(*cg, &st); err != nil {
		log.Fatal(err)
	}
	level := uint32(strings.Count(strings.TrimPrefix(*cg, "/sys/fs/cgroup"), "/"))
	spec, err := ebpf.LoadCollectionSpec(*obj)
	if err != nil {
		log.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatal(err)
	}
	defer coll.Close()
	if err := coll.Maps["spike_cfg"].Put(uint32(0), config{AgentsID: st.Ino, AgentsLevel: level}); err != nil {
		log.Fatal(err)
	}
	l, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["exec_hash"]})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		log.Fatal(err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; rd.Close() }()
	log.Printf("attached; cgroup %s id %d level %d", *cg, st.Ino, level)
	var n, hits, stale int
	var hitNs, hashNs uint64
	for {
		rec, err := rd.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		var e event
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			log.Fatal(err)
		}
		n++
		hashNs += uint64(e.HashNs)
		if e.Hit == 1 {
			hits++
			hitNs += uint64(e.LookupNs)
		}
		if e.Stale == 1 {
			stale++
		}
		fmt.Printf("ino=%d gen=%d ver=%d ctime=%d.%09d hit=%d stale=%d lookup=%dns hash=%dns ret=%d sb_iversion=%d magic=%#x %s\n",
			e.Ino, e.Gen, e.Version, e.CtimeSec, e.CtimeNsec, e.Hit, e.Stale, e.LookupNs, e.HashNs, e.Ret, e.SBIVer, e.Magic, hex.EncodeToString(e.Hash[:]))
	}
	if n > 0 {
		fmt.Printf("SUMMARY execs=%d hits=%d stale=%d mean_hash=%dns", n, hits, stale, hashNs/uint64(n))
		if hits > 0 {
			fmt.Printf(" mean_hit_lookup=%dns", hitNs/uint64(hits))
		}
		fmt.Println()
	}
}
