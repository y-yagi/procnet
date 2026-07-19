//go:build ebpf_generated

package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/y-yagi/procnet/internal/procmap"
)

// protoTCP/protoUDP mirror PROC_PROTO_TCP/PROC_PROTO_UDP in
// bpf/attribute.bpf.c.
const (
	protoTCP uint8 = 0
	protoUDP uint8 = 1
)

// flowKey mirrors struct flow_key in bpf/attribute.bpf.c byte-for-byte,
// including the explicit padding: bpf2go was not asked to generate a Go
// type for it (gen.go's go:generate line has no -type flag), and the LRU
// map compares keys as raw bytes, so the field layout and the encoding used
// to fill Laddr/Raddr below (native byte order, matching how the BPF map
// marshals Go values) both have to agree with the C struct exactly.
type flowKey struct {
	Proto uint8
	_pad  [3]uint8
	Laddr uint32
	Raddr uint32
	Lport uint16
	Rport uint16
}

// procInfo mirrors struct proc_info in bpf/attribute.bpf.c.
type procInfo struct {
	Pid  uint32
	Comm [16]byte
}

// Source loads the compiled eBPF program(s) that populate the flow_pids map
// in-kernel and lets the /proc-based resolver consult it before falling
// back to its own logic (see procmap.FlowResolver). It requires a
// BTF-enabled kernel (CO-RE, fentry) and CAP_BPF/CAP_SYS_ADMIN (root).
type Source struct {
	objs  attributeObjects
	links []link.Link
}

// NewSource loads the eBPF program and attaches its fentry hooks. Any
// returned error means "eBPF unavailable here" -- callers (see
// cmd/procnet/main.go's --ebpf=auto handling) should treat that as
// non-fatal and continue with /proc-only attribution.
func NewSource() (*Source, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpf: removing memlock rlimit: %w", err)
	}

	var objs attributeObjects
	if err := loadAttributeObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("ebpf: loading objects: %w", err)
	}

	s := &Source{objs: objs}

	tcpLink, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceTcpSendmsg})
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("ebpf: attaching fentry/tcp_sendmsg: %w", err)
	}
	s.links = append(s.links, tcpLink)

	udpLink, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceUdpSendmsg})
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("ebpf: attaching fentry/udp_sendmsg: %w", err)
	}
	s.links = append(s.links, udpLink)

	return s, nil
}

// LookupFlow implements procmap.FlowResolver by querying flow_pids.
// IPv6 addresses always return ok=false: the kernel side only tracks IPv4
// (see attribute.bpf.c), so those flows fall back to /proc.
func (s *Source) LookupFlow(proto procmap.Proto, localIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16) (pid int, comm string, ok bool) {
	l4 := localIP.To4()
	r4 := remoteIP.To4()
	if l4 == nil || r4 == nil {
		return 0, "", false
	}

	var p uint8
	switch proto {
	case procmap.ProtoTCP:
		p = protoTCP
	case procmap.ProtoUDP:
		p = protoUDP
	default:
		return 0, "", false
	}

	// Native byte order here (not Big/LittleEndian specifically): the BPF
	// side stores the IPv4 address's raw wire-format bytes directly into a
	// plain integer field, and the ebpf library marshals Go map keys in the
	// host's native order, so re-interpreting l4/r4 with binary.NativeEndian
	// is what reproduces the same in-memory byte pattern the kernel wrote.
	key := flowKey{
		Proto: p,
		Laddr: binary.NativeEndian.Uint32(l4),
		Raddr: binary.NativeEndian.Uint32(r4),
		Lport: localPort,
		Rport: remotePort,
	}

	var val procInfo
	if err := s.objs.FlowPids.Lookup(&key, &val); err != nil {
		return 0, "", false
	}

	name := string(val.Comm[:])
	if idx := indexNUL(name); idx >= 0 {
		name = name[:idx]
	}
	return int(val.Pid), name, true
}

// Close detaches the fentry links and releases the loaded map/program fds.
func (s *Source) Close() error {
	var firstErr error
	for _, l := range s.links {
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := s.objs.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// indexNUL returns the index of the first NUL byte in s, or -1 if none
// (bpf_get_current_comm's output is NUL-terminated/padded, like a C string).
func indexNUL(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return i
		}
	}
	return -1
}
