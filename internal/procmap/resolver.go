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
	// missRefreshInterval bounds how often Lookup re-reads /proc/net/* on a
	// cache miss. This is separate from (and much shorter than)
	// refreshInterval: rebuilding just the socket tables is cheap text
	// parsing, so it's safe to redo more often, but a flood of misses for
	// unattributable traffic (e.g. multicast) must still not cause a
	// re-read on every single packet.
	missRefreshInterval = 150 * time.Millisecond
	// negativeTTL is how long an unresolvable 5-tuple is remembered as such,
	// so repeated misses for the same tuple short-circuit instead of
	// re-triggering an on-demand /proc/net refresh and fd walk. Kept short
	// so a connection that becomes resolvable shortly after (e.g. the
	// owning process's fd shows up on the next full refresh) isn't stuck
	// negative for long.
	negativeTTL = 1 * time.Second
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

	// procRoot is normally "/proc"; it exists as a field so tests can point
	// it at a fixture directory tree.
	procRoot string

	lastRefresh     time.Time
	lastMissRefresh time.Time
	exact           map[tupleKey]uint64 // proto+local+remote -> inode
	byLocal         map[localKey]uint64 // proto+local -> inode (fallback, last-wins)
	inodeToPID      map[uint64]int

	tuples   map[tupleKey]cachedPID
	negative map[tupleKey]time.Time // unresolvable tuples, cached briefly to skip re-work
}

// NewResolver returns a Resolver with an empty cache. The first Lookup call
// triggers the initial /proc walk.
func NewResolver() *Resolver {
	return &Resolver{
		procRoot: "/proc",
		tuples:   make(map[tupleKey]cachedPID),
		negative: make(map[tupleKey]time.Time),
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

	if inode, found := r.lookupInodeLocked(key, proto, localIP, localPort); found {
		if pid, found2 := r.inodeToPID[inode]; found2 {
			return r.remember(key, pid, now)
		}
	}

	if c, found := r.tuples[key]; found && now.Before(c.expires) {
		return c.pid, c.name, true
	}

	// Every existing cache missed. Check the short-TTL negative cache next:
	// if we already know this exact tuple was unresolvable a moment ago,
	// bail out now instead of redoing the on-demand work below on every
	// packet of an unattributable flow (e.g. multicast noise).
	if exp, found := r.negative[key]; found && now.Before(exp) {
		return 0, "", false
	}

	// On-demand resolution: the flow may have opened after the last
	// periodic refresh, so re-read just the (cheap) socket tables and
	// retry the lookup. This re-read is independently rate-limited via
	// lastMissRefresh/missRefreshInterval, separate from the full refresh's
	// 1s cadence, so a burst of misses can't force a /proc/net re-read on
	// every packet.
	r.refreshSocketTablesLocked(now)

	if inode, found := r.lookupInodeLocked(key, proto, localIP, localPort); found {
		if pid, found2 := r.inodeToPID[inode]; found2 {
			return r.remember(key, pid, now)
		}

		// The socket itself is now known, but its owning PID isn't in our
		// cached inode map yet (e.g. the process's fd appeared after the
		// last full /proc/*/fd walk). Resolve just this one inode instead
		// of rebuilding the whole map. NOTE: this runs while r.mu is held;
		// it's bounded by stopping at the first matching fd, but is still
		// an O(processes) scan in the worst case, so it must stay on the
		// rare miss path only.
		if pid, ok := resolveInodeToPID(r.procRoot, inode); ok {
			r.inodeToPID[inode] = pid
			return r.remember(key, pid, now)
		}
	}

	r.negative[key] = now.Add(negativeTTL)
	return 0, "", false
}

// lookupInodeLocked resolves key's socket inode via the exact tuple table,
// falling back to the local-address-only table (including the 0.0.0.0/::
// wildcard bind used by server sockets). Callers must hold r.mu.
func (r *Resolver) lookupInodeLocked(key tupleKey, proto Proto, localIP net.IP, localPort uint16) (uint64, bool) {
	if inode, found := r.exact[key]; found {
		return inode, true
	}

	lk := localKey{proto: proto, ip: localIP.String(), port: localPort}
	if inode, found := r.byLocal[lk]; found {
		return inode, true
	}

	// Wildcard-bound fallback: server sockets often listen on 0.0.0.0 / ::.
	wildcard := "0.0.0.0"
	if localIP.To4() == nil {
		wildcard = "::"
	}
	lk.ip = wildcard
	if inode, found := r.byLocal[lk]; found {
		return inode, true
	}

	return 0, false
}

func (r *Resolver) remember(key tupleKey, pid int, now time.Time) (int, string, bool) {
	name := processName(pid)
	r.tuples[key] = cachedPID{pid: pid, name: name, expires: now.Add(tupleTTL)}
	delete(r.negative, key)
	return pid, name, true
}

// buildSocketTables parses /proc/net/{tcp,tcp6,udp,udp6} into fresh exact
// and byLocal tables. It does not touch r's fields or the (expensive)
// inode->PID map, so it's cheap enough to call from the on-demand miss
// path as well as the periodic full refresh.
func (r *Resolver) buildSocketTables() (map[tupleKey]uint64, map[localKey]uint64) {
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
	addEntries(ProtoTCP, r.procRoot+"/net/tcp")
	addEntries(ProtoTCP, r.procRoot+"/net/tcp6")
	addEntries(ProtoUDP, r.procRoot+"/net/udp")
	addEntries(ProtoUDP, r.procRoot+"/net/udp6")

	return exact, byLocal
}

// refreshLocked rebuilds the socket and inode tables if the cache has gone
// stale. Callers must hold r.mu.
func (r *Resolver) refreshLocked() {
	now := time.Now()
	if !r.lastRefresh.IsZero() && now.Sub(r.lastRefresh) < refreshInterval {
		return
	}
	r.lastRefresh = now

	exact, byLocal := r.buildSocketTables()

	inodeToPID, err := buildInodeToPID(r.procRoot)
	if err != nil {
		inodeToPID = r.inodeToPID // keep stale data rather than losing it
	}

	r.exact = exact
	r.byLocal = byLocal
	if inodeToPID != nil {
		r.inodeToPID = inodeToPID
	}

	// Prune expired cache entries opportunistically.
	for k, c := range r.tuples {
		if now.After(c.expires) {
			delete(r.tuples, k)
		}
	}
	for k, exp := range r.negative {
		if now.After(exp) {
			delete(r.negative, k)
		}
	}
}

// refreshSocketTablesLocked re-reads only /proc/net/{tcp,tcp6,udp,udp6} (the
// cheap half of a full refresh, skipping the /proc/*/fd walk) so a flow that
// opened after the last periodic refresh can be found immediately on a
// cache miss. It is rate-limited independently of refreshLocked, via
// lastMissRefresh/missRefreshInterval, so a burst of unresolvable lookups
// can't force a re-read on every packet. Callers must hold r.mu.
func (r *Resolver) refreshSocketTablesLocked(now time.Time) {
	if !r.lastMissRefresh.IsZero() && now.Sub(r.lastMissRefresh) < missRefreshInterval {
		return
	}
	r.lastMissRefresh = now

	r.exact, r.byLocal = r.buildSocketTables()
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
