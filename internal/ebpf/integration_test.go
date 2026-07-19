//go:build ebpf_integration && ebpf_generated

// This file only compiles once the eBPF object has actually been generated
// (ebpf_generated) and the caller explicitly opts into a real kernel load
// (ebpf_integration) -- e.g.:
//
//	sudo go test -tags 'ebpf_generated ebpf_integration' ./internal/ebpf/...
//
// It is not part of the default `go test ./...` run, since it requires
// root and a BTF-enabled kernel to load and attach real BPF programs.
package ebpf

import (
	"net"
	"os"
	"testing"

	"github.com/y-yagi/procnet/internal/procmap"
)

// TestSourceLoopbackTCP loads the real eBPF program, opens a loopback TCP
// connection from this test process, and checks that flow_pids picked up
// this process's own pid for that flow -- i.e. that the fentry/tcp_sendmsg
// hook and LookupFlow's key encoding actually agree with each other and
// with the kernel.
func TestSourceLoopbackTCP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF/CAP_SYS_ADMIN) to load eBPF programs")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skip("requires a BTF-enabled kernel (/sys/kernel/btf/vmlinux not found)")
	}

	src, err := NewSource()
	if err != nil {
		t.Skipf("eBPF unavailable on this kernel: %v", err)
	}
	defer src.Close()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	server := <-accepted
	defer server.Close()

	localAddr := conn.LocalAddr().(*net.TCPAddr)
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)

	pid, comm, ok := src.LookupFlow(procmap.ProtoTCP, localAddr.IP, uint16(localAddr.Port), remoteAddr.IP, uint16(remoteAddr.Port))
	if !ok {
		t.Fatal("LookupFlow: no entry found for the connection just made from this process")
	}
	if pid != os.Getpid() {
		t.Fatalf("LookupFlow pid = %d, want this test process's pid %d (comm=%q)", pid, os.Getpid(), comm)
	}
}
