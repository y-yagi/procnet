package procmap

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// refreshInterval bounds how often the (expensive) /proc/net + /proc/*/fd
	// walk is redone.
	refreshInterval = 1 * time.Second
	// tupleTTL is how long a resolved 5-tuple->PID mapping is trusted after
	// its /proc/net entry can no longer be found, so short-lived
	// connections that have already closed are still attributed correctly.
	tupleTTL = 5 * time.Second
)

// localKey identifies a bound local socket endpoint.
type localKey struct {
	proto Proto
	ip    string
	port  uint16
}

// tupleKey identifies a full flow (both endpoints), used for the resilient
// short-TTL cache.
type tupleKey struct {
	proto      Proto
	localIP    string
	localPort  uint16
	remoteIP   string
	remotePort uint16
}

type cachedPID struct {
	pid     int
	name    string
	expires time.Time
}

// Resolver maps live network flows to the local process that owns them, by
// periodically parsing /proc/net/{tcp,tcp6,udp,udp6} and /proc/*/fd/*. It is
// safe for concurrent use.
type Resolver struct {
	mu sync.Mutex

	lastRefresh time.Time
	exact       map[tupleKey]uint64 // proto+local+remote -> inode
	byLocal     map[localKey]uint64 // proto+local -> inode (fallback, last-wins)
	inodeToPID  map[uint64]int

	tuples map[tupleKey]cachedPID
}

// NewResolver returns a Resolver with an empty cache. The first Lookup call
// triggers the initial /proc walk.
func NewResolver() *Resolver {
	return &Resolver{
		tuples: make(map[tupleKey]cachedPID),
	}
}

// Lookup resolves the process owning the local socket (localIP, localPort)
// connected to (remoteIP, remotePort) over proto. ok is false if no owning
// process could be determined.
func (r *Resolver) Lookup(proto Proto, localIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16) (pid int, name string, ok bool) {
	key := tupleKey{
		proto:      proto,
		localIP:    localIP.String(),
		localPort:  localPort,
		remoteIP:   remoteIP.String(),
		remotePort: remotePort,
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.refreshLocked()

	now := time.Now()

	if inode, found := r.exact[key]; found {
		if pid, found2 := r.inodeToPID[inode]; found2 {
			return r.remember(key, pid, now)
		}
	}

	lk := localKey{proto: proto, ip: localIP.String(), port: localPort}
	if inode, found := r.byLocal[lk]; found {
		if pid, found2 := r.inodeToPID[inode]; found2 {
			return r.remember(key, pid, now)
		}
	}

	// Wildcard-bound fallback: server sockets often listen on 0.0.0.0 / ::.
	wildcard := "0.0.0.0"
	if localIP.To4() == nil {
		wildcard = "::"
	}
	lk.ip = wildcard
	if inode, found := r.byLocal[lk]; found {
		if pid, found2 := r.inodeToPID[inode]; found2 {
			return r.remember(key, pid, now)
		}
	}

	if c, found := r.tuples[key]; found && now.Before(c.expires) {
		return c.pid, c.name, true
	}

	return 0, "", false
}

func (r *Resolver) remember(key tupleKey, pid int, now time.Time) (int, string, bool) {
	name := processName(pid)
	r.tuples[key] = cachedPID{pid: pid, name: name, expires: now.Add(tupleTTL)}
	return pid, name, true
}

// refreshLocked rebuilds the socket and inode tables if the cache has gone
// stale. Callers must hold r.mu.
func (r *Resolver) refreshLocked() {
	now := time.Now()
	if !r.lastRefresh.IsZero() && now.Sub(r.lastRefresh) < refreshInterval {
		return
	}
	r.lastRefresh = now

	exact := make(map[tupleKey]uint64)
	byLocal := make(map[localKey]uint64)

	addEntries := func(proto Proto, path string) {
		entries, err := readNetFile(path)
		if err != nil {
			return
		}
		for _, e := range entries {
			tk := tupleKey{
				proto:      proto,
				localIP:    e.LocalIP.String(),
				localPort:  e.Local,
				remoteIP:   e.RemoteIP.String(),
				remotePort: e.Remote,
			}
			exact[tk] = e.Inode
			byLocal[localKey{proto: proto, ip: e.LocalIP.String(), port: e.Local}] = e.Inode
		}
	}
	addEntries(ProtoTCP, "/proc/net/tcp")
	addEntries(ProtoTCP, "/proc/net/tcp6")
	addEntries(ProtoUDP, "/proc/net/udp")
	addEntries(ProtoUDP, "/proc/net/udp6")

	inodeToPID, err := buildInodeToPID()
	if err != nil {
		inodeToPID = r.inodeToPID // keep stale data rather than losing it
	}

	r.exact = exact
	r.byLocal = byLocal
	if inodeToPID != nil {
		r.inodeToPID = inodeToPID
	}

	// Prune expired tuple cache entries opportunistically.
	for k, c := range r.tuples {
		if now.After(c.expires) {
			delete(r.tuples, k)
		}
	}
}

// DefaultInterface returns the name of the network interface used by the
// default IPv4 route (the Destination=00000000 row of /proc/net/route),
// which is the interface a tethered phone connection typically appears as
// once it becomes the system's default route.
func DefaultInterface() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue // header
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		iface, dest := fields[0], fields[1]
		if dest == "00000000" {
			return iface, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", os.ErrNotExist
}
