// Package aggregate maintains per-process byte counters (sent/received,
// cumulative totals, and smoothed rates) fed by a stream of attributed
// packets.
package aggregate

import (
	"sort"
	"sync"
	"time"
)

// ewmaAlpha controls how quickly the displayed rate reacts to change.
// Smaller = smoother/slower, larger = snappier/noisier.
const ewmaAlpha = 0.3

// unknownKey is the pseudo-process bucket for packets that could not be
// attributed to any local process.
const unknownKey = -1

// Stats holds the accumulated counters for a single process.
type Stats struct {
	PID  int
	Name string

	SentBytes uint64
	RecvBytes uint64

	SentRate float64 // EWMA-smoothed bytes/sec
	RecvRate float64

	// internal, used to compute deltas between Snapshot calls
	prevSent uint64
	prevRecv uint64
}

// TotalBytes returns cumulative sent+received bytes.
func (s Stats) TotalBytes() uint64 { return s.SentBytes + s.RecvBytes }

// TotalRate returns the combined sent+recv EWMA rate in bytes/sec.
func (s Stats) TotalRate() float64 { return s.SentRate + s.RecvRate }

// Aggregator accumulates per-process traffic counters and periodically
// recomputes smoothed rates. It is safe for concurrent use.
type Aggregator struct {
	mu       sync.Mutex
	counters map[int]*Stats
	lastTick time.Time
	started  time.Time
}

// New returns an empty Aggregator.
func New() *Aggregator {
	now := time.Now()
	return &Aggregator{
		counters: make(map[int]*Stats),
		lastTick: now,
		started:  now,
	}
}

// AddSent records sentBytes for the given process (identified by pid/name).
// Use pid < 0 (e.g. -1) with name "unknown" for unattributed traffic.
func (a *Aggregator) AddSent(pid int, name string, n uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.counter(pid, name).SentBytes += n
}

// AddRecv records recvBytes for the given process.
func (a *Aggregator) AddRecv(pid int, name string, n uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.counter(pid, name).RecvBytes += n
}

func (a *Aggregator) counter(pid int, name string) *Stats {
	c, ok := a.counters[pid]
	if !ok {
		c = &Stats{PID: pid, Name: name}
		a.counters[pid] = c
	} else if name != "" {
		c.Name = name // keep name fresh (comm can change, pid reuse, etc.)
	}
	return c
}

// Tick recomputes EWMA rates based on the delta since the previous Tick
// call and the elapsed wall time. Call it roughly once per second.
func (a *Aggregator) Tick() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	interval := now.Sub(a.lastTick).Seconds()
	a.lastTick = now
	if interval <= 0 {
		return
	}

	for _, c := range a.counters {
		sentDelta := float64(c.SentBytes - c.prevSent)
		recvDelta := float64(c.RecvBytes - c.prevRecv)
		c.prevSent = c.SentBytes
		c.prevRecv = c.RecvBytes

		sentInstant := sentDelta / interval
		recvInstant := recvDelta / interval

		c.SentRate = ewmaAlpha*sentInstant + (1-ewmaAlpha)*c.SentRate
		c.RecvRate = ewmaAlpha*recvInstant + (1-ewmaAlpha)*c.RecvRate
	}
}

// Snapshot returns a copy of all current per-process stats, sorted by
// descending total bytes.
func (a *Aggregator) Snapshot() []Stats {
	a.mu.Lock()
	defer a.mu.Unlock()

	out := make([]Stats, 0, len(a.counters))
	for _, c := range a.counters {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].TotalBytes() > out[j].TotalBytes()
	})
	return out
}

// Reset clears all counters and restarts the uptime clock's tick baseline
// (uptime itself, tracked via Uptime, is left running).
func (a *Aggregator) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.counters = make(map[int]*Stats)
	a.lastTick = time.Now()
}

// Uptime returns how long this Aggregator has been running.
func (a *Aggregator) Uptime() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	return time.Since(a.started)
}

// Totals returns the sum of sent/recv bytes across all processes.
func (a *Aggregator) Totals() (sent, recv uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, c := range a.counters {
		sent += c.SentBytes
		recv += c.RecvBytes
	}
	return sent, recv
}

// UnknownPID is the sentinel PID used for traffic that could not be
// attributed to a process.
const UnknownPID = unknownKey

// UnknownName is the display name paired with UnknownPID.
const UnknownName = "unknown"
