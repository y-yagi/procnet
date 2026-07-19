//go:build ignore

// attribute.bpf.c populates a 5-tuple -> {pid,comm} LRU map at send time, so
// that internal/procmap's resolver can attribute a flow to a process on its
// very first packet instead of waiting for a /proc/net snapshot (or missing
// short/sub-second flows entirely -- see CLAUDE.md's "Known limitations").
//
// Scope: IPv4 + connected sockets only.
//   - IPv6 (skc_family != AF_INET) is skipped; those flows fall back to the
//     /proc path.
//   - Unconnected UDP (a bare sendto(), skc_daddr == 0 because connect() was
//     never called) is skipped for the same reason: there is no remote
//     endpoint yet to key the map on.
//
// Requires a BTF-enabled kernel (CO-RE, fentry) -- see gen.go for the
// regeneration steps this source needs (clang/llvm-strip, bpftool for
// vmlinux.h, and libbpf's bpf_helpers.h/bpf_core_read.h/bpf_tracing.h/
// bpf_endian.h available on the include path).
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define AF_INET 2

#define PROC_PROTO_TCP 0
#define PROC_PROTO_UDP 1

// flow_key mirrors procmap's 5-tuple: local=source (the sending socket),
// remote=destination. Field order/sizes/padding here must match the Go
// flowKey struct in source.go byte-for-byte, since bpf2go was not asked to
// generate a Go type for it (see gen.go's go:generate line -- no -type flag)
// and the LRU map is keyed by raw bytes.
struct flow_key {
	__u8 proto; // PROC_PROTO_TCP or PROC_PROTO_UDP
	__u8 _pad[3];
	__be32 laddr;
	__be32 raddr;
	__u16 lport; // host order (skc_num is already host order)
	__u16 rport; // host order (bpf_ntohs(skc_dport))
};

// proc_info is the map value: the process that owns the sending socket.
struct proc_info {
	__u32 pid;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow_key);
	__type(value, struct proc_info);
} flow_pids SEC(".maps");

// record_flow reads the 5-tuple + family off sk and, if it's an IPv4
// connected socket, upserts flow_pids with the current task's pid/comm.
static __always_inline void record_flow(struct sock *sk, __u8 proto)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET)
		return;

	__be32 raddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	if (raddr == 0)
		return; // unconnected UDP (sendto): no remote endpoint yet.

	struct flow_key key = {};
	key.proto = proto;
	key.laddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	key.raddr = raddr;
	key.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	key.rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

	struct proc_info info = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	info.pid = pid_tgid >> 32;
	bpf_get_current_comm(&info.comm, sizeof(info.comm));

	bpf_map_update_elem(&flow_pids, &key, &info, BPF_ANY);
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(trace_tcp_sendmsg, struct sock *sk)
{
	record_flow(sk, PROC_PROTO_TCP);
	return 0;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(trace_udp_sendmsg, struct sock *sk)
{
	record_flow(sk, PROC_PROTO_UDP);
	return 0;
}
