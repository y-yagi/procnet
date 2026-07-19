//go:build !ebpf_generated

// This is the default build of internal/ebpf: it exposes the same exported
// API as source.go (NewSource, (*Source).LookupFlow, (*Source).Close) but
// never references the bpf2go-generated symbols, so `go build ./...` works
// on a machine without an eBPF toolchain (see gen.go). NewSource always
// fails here; callers (cmd/procnet/main.go's --ebpf handling) treat that as
// "eBPF unavailable" and fall back to /proc-only attribution.
package ebpf

import (
	"errors"
	"net"

	"github.com/y-yagi/procnet/internal/procmap"
)

// ErrNotBuilt is returned by NewSource in this build: the eBPF object was
// not compiled in (build without the ebpf_generated tag). Regenerate it
// with clang/llvm-strip installed -- see gen.go -- and rebuild with
// `-tags ebpf_generated` to get a working Source.
var ErrNotBuilt = errors.New("ebpf: not built (regenerate with clang: see internal/ebpf/gen.go, then build with -tags ebpf_generated)")

// Source is the stub implementation's placeholder type; it is never
// constructed successfully in this build (NewSource always errors).
type Source struct{}

// NewSource always returns ErrNotBuilt in this build.
func NewSource() (*Source, error) {
	return nil, ErrNotBuilt
}

// LookupFlow exists only to satisfy procmap.FlowResolver's shape; it is
// unreachable since NewSource never returns a usable *Source.
func (s *Source) LookupFlow(proto procmap.Proto, localIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16) (pid int, comm string, ok bool) {
	return 0, "", false
}

// Close is a no-op in this build.
func (s *Source) Close() error {
	return nil
}
