package procmap

import (
	"os"
	"path/filepath"
	"testing"
)

// mkFakeProc builds a fixture directory tree that looks like /proc for the
// purposes of buildInodeToPID/resolveInodeToPID: a numbered directory per
// fake PID, each with an fd/ subdirectory containing symlinks. The symlink
// targets don't need to resolve to anything real -- only the link text
// itself ("socket:[N]" or otherwise) is read.
func mkFakeProc(t *testing.T, procEntries map[int]map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for pid, fds := range procEntries {
		fdDir := filepath.Join(root, itoa(pid), "fd")
		if err := os.MkdirAll(fdDir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		for name, target := range fds {
			if err := os.Symlink(target, filepath.Join(fdDir, name)); err != nil {
				t.Fatalf("Symlink: %v", err)
			}
		}
	}
	// A non-PID entry (e.g. "self") must be skipped, not walked.
	if err := os.MkdirAll(filepath.Join(root, "self", "fd"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	return root
}

func itoa(n int) string {
	// Avoid importing strconv twice in the test just for this; simple manual
	// conversion is fine for the small non-negative PIDs used in tests.
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func TestBuildInodeToPIDWithRoot(t *testing.T) {
	root := mkFakeProc(t, map[int]map[string]string{
		100: {"3": "socket:[111]", "4": "socket:[222]", "5": "/dev/pts/0"},
		200: {"3": "socket:[333]"},
	})

	got, err := buildInodeToPID(root)
	if err != nil {
		t.Fatalf("buildInodeToPID: %v", err)
	}

	want := map[uint64]int{111: 100, 222: 100, 333: 200}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %v", len(got), len(want), got)
	}
	for inode, pid := range want {
		if got[inode] != pid {
			t.Errorf("inode %d -> pid %d, want %d", inode, got[inode], pid)
		}
	}
}

func TestBuildInodeToPIDMissingRoot(t *testing.T) {
	if _, err := buildInodeToPID("/no/such/proc/root"); err == nil {
		t.Fatal("expected error for missing root, got nil")
	}
}

func TestResolveInodeToPIDFindsTarget(t *testing.T) {
	root := mkFakeProc(t, map[int]map[string]string{
		100: {"3": "socket:[111]"},
		200: {"3": "socket:[999]", "4": "socket:[222]"},
	})

	pid, ok := resolveInodeToPID(root, 222)
	if !ok || pid != 200 {
		t.Fatalf("resolveInodeToPID(222) = (%d, %v), want (200, true)", pid, ok)
	}
}

func TestResolveInodeToPIDNotFound(t *testing.T) {
	root := mkFakeProc(t, map[int]map[string]string{
		100: {"3": "socket:[111]"},
	})

	pid, ok := resolveInodeToPID(root, 42)
	if ok {
		t.Fatalf("resolveInodeToPID(42) = (%d, %v), want ok=false", pid, ok)
	}
}

func TestResolveInodeToPIDMissingRoot(t *testing.T) {
	pid, ok := resolveInodeToPID("/no/such/proc/root", 1)
	if ok {
		t.Fatalf("resolveInodeToPID on missing root = (%d, %v), want ok=false", pid, ok)
	}
}
