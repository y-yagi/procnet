package aggregate

import (
	"math"
	"testing"
	"time"
)

func TestAddAndSnapshotCumulative(t *testing.T) {
	a := New()
	a.AddSent(100, "curl", 500)
	a.AddRecv(100, "curl", 1500)
	a.AddSent(100, "curl", 250)

	snap := a.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("got %d entries, want 1", len(snap))
	}
	s := snap[0]
	if s.SentBytes != 750 {
		t.Errorf("SentBytes = %d, want 750", s.SentBytes)
	}
	if s.RecvBytes != 1500 {
		t.Errorf("RecvBytes = %d, want 1500", s.RecvBytes)
	}
	if s.TotalBytes() != 2250 {
		t.Errorf("TotalBytes = %d, want 2250", s.TotalBytes())
	}
}

func TestSnapshotSortedByTotalDescending(t *testing.T) {
	a := New()
	a.AddSent(1, "small", 100)
	a.AddSent(2, "big", 10000)
	a.AddSent(3, "medium", 1000)

	snap := a.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("got %d entries, want 3", len(snap))
	}
	if snap[0].PID != 2 || snap[1].PID != 3 || snap[2].PID != 1 {
		t.Errorf("order = [%d,%d,%d], want [2,3,1]", snap[0].PID, snap[1].PID, snap[2].PID)
	}
}

func TestUnknownBucket(t *testing.T) {
	a := New()
	a.AddRecv(UnknownPID, UnknownName, 42)
	snap := a.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("got %d entries, want 1", len(snap))
	}
	if snap[0].PID != UnknownPID || snap[0].Name != UnknownName {
		t.Errorf("got pid=%d name=%q, want pid=%d name=%q", snap[0].PID, snap[0].Name, UnknownPID, UnknownName)
	}
}

func TestTickComputesRate(t *testing.T) {
	a := New()
	// Force a known interval by manipulating lastTick directly.
	a.lastTick = time.Now().Add(-1 * time.Second)
	a.AddSent(1, "proc", 1000) // 1000 bytes over ~1s => ~1000 B/s instantaneous

	a.Tick()

	snap := a.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("got %d entries, want 1", len(snap))
	}
	// EWMA on first tick: rate = alpha*instant + (1-alpha)*0 = alpha*instant.
	want := ewmaAlpha * 1000.0
	got := snap[0].SentRate
	// Allow tolerance for the real (slightly >1s) elapsed wall time.
	if math.Abs(got-want) > want*0.5 {
		t.Errorf("SentRate = %.2f, want approx %.2f", got, want)
	}
	if got <= 0 {
		t.Errorf("SentRate should be positive after traffic, got %.2f", got)
	}
}

func TestTickRateDecaysWithoutTraffic(t *testing.T) {
	a := New()
	a.lastTick = time.Now().Add(-1 * time.Second)
	a.AddSent(1, "proc", 1000)
	a.Tick()

	first := a.Snapshot()[0].SentRate

	// Second tick with no new traffic: rate should decay towards zero but
	// not reset to it (EWMA smoothing).
	a.lastTick = time.Now().Add(-1 * time.Second)
	a.Tick()
	second := a.Snapshot()[0].SentRate

	if second >= first {
		t.Errorf("rate did not decay: first=%.2f second=%.2f", first, second)
	}
	if second <= 0 {
		t.Errorf("rate should still be positive (smoothed), got %.2f", second)
	}
}

func TestReset(t *testing.T) {
	a := New()
	a.AddSent(1, "proc", 1000)
	a.Reset()
	if snap := a.Snapshot(); len(snap) != 0 {
		t.Errorf("got %d entries after Reset, want 0", len(snap))
	}
}

func TestTotals(t *testing.T) {
	a := New()
	a.AddSent(1, "a", 100)
	a.AddRecv(1, "a", 200)
	a.AddSent(2, "b", 50)

	sent, recv := a.Totals()
	if sent != 150 {
		t.Errorf("sent = %d, want 150", sent)
	}
	if recv != 200 {
		t.Errorf("recv = %d, want 200", recv)
	}
}

func TestNameUpdatesOnSubsequentAdd(t *testing.T) {
	a := New()
	a.AddSent(1, "old-name", 10)
	a.AddSent(1, "new-name", 10)
	snap := a.Snapshot()
	if snap[0].Name != "new-name" {
		t.Errorf("Name = %q, want %q", snap[0].Name, "new-name")
	}
}
