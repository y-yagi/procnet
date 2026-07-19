// Package ebpf provides eBPF-based process attribution for procnet: a
// BPF_MAP_TYPE_LRU_HASH ("flow_pids") populated in-kernel at send time by
// CO-RE fentry programs on tcp_sendmsg/udp_sendmsg (see
// bpf/attribute.bpf.c), keyed by the same (proto, local, remote) 5-tuple
// internal/procmap's resolver already uses, mapping it to the sending
// process's pid+comm.
//
// This lets a flow be attributed on its very first packet, in-kernel,
// instead of depending on a /proc/net snapshot -- closing the gap described
// in CLAUDE.md's "Known limitations" (short/sub-second flows, bursty UDP).
// It does not replace that /proc path: attribution stays hybrid. See
// internal/procmap/resolver.go's FlowResolver interface and Lookup order,
// and cmd/procnet/main.go's --ebpf flag.
//
// # Building the eBPF object
//
// The compiled object (attribute_bpfel.go/.o) is NOT committed yet: this
// checkout's toolchain has bpftool and kernel BTF, but is missing clang and
// llvm-strip (only libclang's dev libraries are installed), so it cannot be
// generated here. Regenerating it elsewhere requires:
//
//  1. clang + llvm-strip (e.g. `apt install clang llvm`).
//  2. bpftool + a BTF-enabled kernel, to emit bpf/vmlinux.h:
//     bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/ebpf/bpf/vmlinux.h
//  3. libbpf's CO-RE headers (bpf_helpers.h, bpf_core_read.h,
//     bpf_tracing.h, bpf_endian.h) reachable from bpf/attribute.bpf.c's
//     include path (alongside vmlinux.h under internal/ebpf/bpf/, or via
//     an extra -I on the go:generate line below).
//
// Then run:
//
//	go generate ./internal/ebpf
//
// which produces internal/ebpf/attribute_bpfel.go and .../attribute_bpfel.o.
// Those, plus bpf/vmlinux.h, should be committed so that a plain `go build`
// keeps working for everyone else without a local eBPF toolchain -- but the
// *default* build of this package (source_stub.go, no build tag) never
// needs them: source.go, which references the bpf2go-generated
// attributeObjects/loadAttributeObjects symbols, is gated behind the
// `ebpf_generated` build tag and must be built with `-tags ebpf_generated`.
package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -tags ebpf_generated -target bpfel attribute ./bpf/attribute.bpf.c -- -I./bpf
