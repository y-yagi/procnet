//go:build !ebpf_generated

package ebpf

import "testing"

// TestNewSourceStubReturnsError pins down the fallback contract this
// package promises the rest of the codebase (see cmd/procnet/main.go's
// --ebpf handling and CLAUDE.md): in the default build -- no
// ebpf_generated tag, i.e. no eBPF toolchain available -- NewSource must
// fail clearly rather than panic or silently return a non-functional
// Source, so callers can fall back to /proc attribution.
func TestNewSourceStubReturnsError(t *testing.T) {
	s, err := NewSource()
	if err == nil {
		t.Fatal("NewSource() error = nil, want a non-nil error in the default (!ebpf_generated) build")
	}
	if s != nil {
		t.Fatalf("NewSource() Source = %v, want nil on error", s)
	}
	if err != ErrNotBuilt {
		t.Fatalf("NewSource() error = %v, want ErrNotBuilt", err)
	}
}
