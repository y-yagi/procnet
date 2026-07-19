package procmap

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"

// hexIPv4 word-reverses a dotted IPv4 address into the hex form /proc/net/tcp
// uses, mirroring the encoding covered by parse_test.go.
func hexIPv4(t *testing.T, ip string) string {
	t.Helper()
	b := net.ParseIP(ip).To4()
	if b == nil {
		t.Fatalf("not an IPv4 address: %q", ip)
	}
	s := ""
	for i := 3; i >= 0; i-- {
		s += byteToHex(b[i])
	}
	return s
}

func hexPort(port uint16) string {
	return fmt.Sprintf("%04X", port)
}

// tcpLine renders one data row of /proc/net/tcp with enough columns for
// parseNetFile (which only reads fields[1], [2] and [9]).
func tcpLine(t *testing.T, idx int, localIP string, localPort uint16, remoteIP string, remotePort uint16, inode uint64) string {
	t.Helper()
	return fmt.Sprintf("  %d: %s:%s %s:%s 0A 00000000:00000000 00:00000000 00000000  1000        0 %d 1 0000000000000000 100 0 0 10 0",
		idx, hexIPv4(t, localIP), hexPort(localPort), hexIPv4(t, remoteIP), hexPort(remotePort), inode)
}

// writeTCPFile (re)writes root/net/tcp with the given data lines.
func writeTCPFile(t *testing.T, root string, lines ...string) {
	t.Helper()
	netDir := filepath.Join(root, "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	content := tcpHeader + "\n"
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// addFakeFD registers a socket fd for pid in the fixture proc tree.
func addFakeFD(t *testing.T, root string, pid int, fd int, target string) {
	t.Helper()
	fdDir := filepath.Join(root, itoa(pid), "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(fdDir, itoa(fd))); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
}

// fakeFlowResolver is a minimal, hermetic FlowResolver test double (standing
// in for internal/ebpf's Source, which this package deliberately does not
// import -- see resolver.go's FlowResolver doc comment). It answers purely
// from fields set by the test and counts invocations, so tests can assert
// on the tuples-cache short-circuit without any real eBPF or /proc
// involvement.
type fakeFlowResolver struct {
	calls int
	pid   int
	comm  string
	ok    bool
}

func (f *fakeFlowResolver) LookupFlow(proto Proto, localIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16) (int, string, bool) {
	f.calls++
	return f.pid, f.comm, f.ok
}

// TestResolverFlowResolverHitSkipsProc checks that a FlowResolver hit is
// trusted directly: the flow resolves correctly even though the fixture
// /proc tree has nothing that could ever resolve it on its own, and the
// FlowResolver's comm is used verbatim as the returned name.
func TestResolverFlowResolverHitSkipsProc(t *testing.T) {
	root := t.TempDir()
	writeTCPFile(t, root) // deliberately empty: /proc alone can't resolve this

	r := NewResolver()
	r.procRoot = root

	fr := &fakeFlowResolver{pid: 777, comm: "curl", ok: true}
	r.SetFlowResolver(fr)

	local := net.ParseIP("10.0.0.5")
	remote := net.ParseIP("93.184.216.34")
	pid, name, ok := r.Lookup(ProtoTCP, local, 54321, remote, 443)
	if !ok || pid != 777 || name != "curl" {
		t.Fatalf("Lookup = (%d, %q, %v), want (777, \"curl\", true)", pid, name, ok)
	}
	if fr.calls != 1 {
		t.Fatalf("FlowResolver.LookupFlow calls = %d, want 1", fr.calls)
	}
}

// TestResolverFlowResolverMissFallsBackToProc checks that a FlowResolver
// miss (ok=false, e.g. an IPv6 flow it doesn't track) doesn't stop
// resolution: Lookup must still fall back to the existing /proc-based
// logic, unchanged.
func TestResolverFlowResolverMissFallsBackToProc(t *testing.T) {
	root := t.TempDir()
	writeTCPFile(t, root, tcpLine(t, 0, "127.0.0.1", 8080, "127.0.0.1", 80, 16314))
	addFakeFD(t, root, 100, 3, "socket:[16314]")

	r := NewResolver()
	r.procRoot = root

	fr := &fakeFlowResolver{ok: false}
	r.SetFlowResolver(fr)

	pid, _, ok := r.Lookup(ProtoTCP, net.ParseIP("127.0.0.1"), 8080, net.ParseIP("127.0.0.1"), 80)
	if !ok || pid != 100 {
		t.Fatalf("Lookup = (%d, _, %v), want (100, _, true) via /proc fallback", pid, ok)
	}
	if fr.calls != 1 {
		t.Fatalf("FlowResolver.LookupFlow calls = %d, want 1", fr.calls)
	}
}

// TestResolverTuplesCacheCheckedBeforeFlowResolver checks that once a flow
// has been resolved (here, via the FlowResolver), its later packets are
// answered entirely from the in-process tuples cache -- Lookup must not
// call LookupFlow again for the same tuple.
func TestResolverTuplesCacheCheckedBeforeFlowResolver(t *testing.T) {
	root := t.TempDir()
	writeTCPFile(t, root) // empty: only the FlowResolver can answer this flow

	r := NewResolver()
	r.procRoot = root

	fr := &fakeFlowResolver{pid: 42, comm: "sshd", ok: true}
	r.SetFlowResolver(fr)

	local := net.ParseIP("10.0.0.9")
	remote := net.ParseIP("10.0.0.10")

	pid, name, ok := r.Lookup(ProtoTCP, local, 2222, remote, 22)
	if !ok || pid != 42 {
		t.Fatalf("first Lookup = (%d, %q, %v), want (42, _, true)", pid, name, ok)
	}
	if fr.calls != 1 {
		t.Fatalf("after first Lookup, FlowResolver calls = %d, want 1", fr.calls)
	}

	pid, name, ok = r.Lookup(ProtoTCP, local, 2222, remote, 22)
	if !ok || pid != 42 {
		t.Fatalf("second Lookup = (%d, %q, %v), want (42, _, true)", pid, name, ok)
	}
	if fr.calls != 1 {
		t.Fatalf("after second Lookup, FlowResolver calls = %d, want still 1 (tuples cache should have short-circuited)", fr.calls)
	}
}

// TestResolverOnDemandResolution exercises the full miss path added to
// Lookup: a flow that only appears in /proc *after* the last periodic
// refresh must still be resolved, via an on-demand re-read of the (cheap)
// socket tables followed by a targeted single-inode fd walk -- without
// waiting for the next full refreshInterval.
func TestResolverOnDemandResolution(t *testing.T) {
	root := t.TempDir()

	// Initial state: one already-known flow, owned by pid 100.
	writeTCPFile(t, root, tcpLine(t, 0, "127.0.0.1", 8080, "127.0.0.1", 80, 16314))
	addFakeFD(t, root, 100, 3, "socket:[16314]")

	r := NewResolver()
	r.procRoot = root

	// Fast path / baseline: first Lookup call triggers the initial full
	// refresh (refreshLocked), which should resolve this via the normal
	// cache, not the on-demand path.
	pid, _, ok := r.Lookup(ProtoTCP, net.ParseIP("127.0.0.1"), 8080, net.ParseIP("127.0.0.1"), 80)
	if !ok || pid != 100 {
		t.Fatalf("baseline Lookup = (%d, %v), want (100, true)", pid, ok)
	}

	// Simulate a new connection that opens *after* that refresh: new
	// /proc/net/tcp row plus a new pid's fd, added to the fixture directly
	// (no call into Resolver yet, so its caches don't know about this).
	writeTCPFile(t, root,
		tcpLine(t, 0, "127.0.0.1", 8080, "127.0.0.1", 80, 16314),
		tcpLine(t, 1, "127.0.0.1", 9090, "127.0.0.1", 81, 20000),
	)
	addFakeFD(t, root, 300, 3, "socket:[20000]")

	// r.lastRefresh was just set, so the full 1s refresh won't fire again;
	// resolution must come from the on-demand miss path.
	pid, _, ok = r.Lookup(ProtoTCP, net.ParseIP("127.0.0.1"), 9090, net.ParseIP("127.0.0.1"), 81)
	if !ok || pid != 300 {
		t.Fatalf("on-demand Lookup = (%d, %v), want (300, true)", pid, ok)
	}

	// A third flow appears immediately afterwards. Because the on-demand
	// socket refresh is itself rate-limited (missRefreshInterval), this
	// lookup -- coming right on the heels of the previous one -- must NOT
	// see it yet.
	writeTCPFile(t, root,
		tcpLine(t, 0, "127.0.0.1", 8080, "127.0.0.1", 80, 16314),
		tcpLine(t, 1, "127.0.0.1", 9090, "127.0.0.1", 81, 20000),
		tcpLine(t, 2, "127.0.0.1", 9091, "127.0.0.1", 82, 30000),
	)
	addFakeFD(t, root, 400, 3, "socket:[30000]")

	if pid, _, ok := r.Lookup(ProtoTCP, net.ParseIP("127.0.0.1"), 9091, net.ParseIP("127.0.0.1"), 82); ok {
		t.Fatalf("rate-limited Lookup unexpectedly resolved: pid=%d", pid)
	}

	// That miss will have been negative-cached, so the retry needs to wait
	// out negativeTTL (not just missRefreshInterval) before the on-demand
	// path is attempted again -- that's the intended interaction between
	// rate limiting and negative caching.
	time.Sleep(negativeTTL + 50*time.Millisecond)
	pid, _, ok = r.Lookup(ProtoTCP, net.ParseIP("127.0.0.1"), 9091, net.ParseIP("127.0.0.1"), 82)
	if !ok || pid != 400 {
		t.Fatalf("post-negative-TTL Lookup = (%d, %v), want (400, true)", pid, ok)
	}
}

// TestResolverNegativeCache checks that an unresolvable tuple is cached
// negatively (so repeated misses don't keep re-triggering /proc work), that
// the negative entry expires so a genuinely-unattributable flow isn't stuck
// forever, and that a successful resolution clears any stale negative entry
// for the same tuple.
func TestResolverNegativeCache(t *testing.T) {
	root := t.TempDir()
	writeTCPFile(t, root) // no entries at all

	r := NewResolver()
	r.procRoot = root

	local := net.ParseIP("10.0.0.1")
	remote := net.ParseIP("10.0.0.2")
	key := tupleKey{proto: ProtoTCP, localIP: local.String(), localPort: 5000, remoteIP: remote.String(), remotePort: 6000}

	if _, _, ok := r.Lookup(ProtoTCP, local, 5000, remote, 6000); ok {
		t.Fatal("Lookup on empty proc tree unexpectedly succeeded")
	}
	if _, found := r.negative[key]; !found {
		t.Fatal("expected a negative cache entry after an unresolvable miss")
	}

	// Immediately after, the on-demand refresh must be short-circuited by
	// the negative cache, even once the rate-limit window has elapsed:
	// lastMissRefresh should not move.
	before := r.lastMissRefresh
	time.Sleep(missRefreshInterval + 50*time.Millisecond)
	if _, _, ok := r.Lookup(ProtoTCP, local, 5000, remote, 6000); ok {
		t.Fatal("Lookup unexpectedly succeeded while still negatively cached")
	}
	if r.lastMissRefresh != before {
		t.Fatal("negative cache did not short-circuit the on-demand refresh")
	}

	// Once the negative TTL has fully expired, the tuple must be retried,
	// and a resolution that has since become available must supersede the
	// stale negative entry.
	writeTCPFile(t, root, tcpLine(t, 0, "10.0.0.1", 5000, "10.0.0.2", 6000, 42))
	addFakeFD(t, root, 500, 3, "socket:[42]")

	time.Sleep(negativeTTL)
	pid, _, ok := r.Lookup(ProtoTCP, local, 5000, remote, 6000)
	if !ok || pid != 500 {
		t.Fatalf("post-expiry Lookup = (%d, %v), want (500, true)", pid, ok)
	}
	if _, found := r.negative[key]; found {
		t.Fatal("negative cache entry should have been cleared on successful resolution")
	}
}
