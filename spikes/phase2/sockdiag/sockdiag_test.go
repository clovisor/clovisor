package sockdiag

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCgroupOfOwnSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	local := netip.MustParseAddrPort(c.LocalAddr().String())
	remote := netip.MustParseAddrPort(c.RemoteAddr().String())

	start := time.Now()
	id, err := CgroupOf(local, remote)
	t.Logf("lookup took %v", time.Since(start))
	if err != nil {
		t.Fatal(err)
	}

	// Our own cgroup id is the inode of our cgroup directory.
	data, _ := os.ReadFile("/proc/self/cgroup")
	path := "/sys/fs/cgroup" + string(data[3:len(data)-1])
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	if id != st.Ino {
		t.Fatalf("cgroup id %d, want %d (%s)", id, st.Ino, path)
	}

	if _, err := CgroupOf(netip.MustParseAddrPort("127.0.0.1:1"), remote); err != ErrNotFound {
		t.Fatalf("missing socket: got %v", err)
	}
}

func BenchmarkCgroupOf(b *testing.B) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	c, _ := net.Dial("tcp", ln.Addr().String())
	defer c.Close()
	local := netip.MustParseAddrPort(c.LocalAddr().String())
	remote := netip.MustParseAddrPort(c.RemoteAddr().String())
	for i := 0; i < b.N; i++ {
		if _, err := CgroupOf(local, remote); err != nil {
			b.Fatal(err)
		}
	}
}
