# CLAUDE.md

procnet is a per-process network bandwidth monitor for Linux, aimed at tracking
which processes consume mobile data while phone-tethered. It captures packets on
one interface and attributes on-wire bytes to processes.

## Build / test

```bash
go build ./...          # or: go build -o procnet ./cmd/procnet
go vet ./...
go test ./...           # unit tests live next to each package
gofmt -l .              # must print nothing
```

Requires Go 1.24.4. Linux-only (AF_PACKET + /proc).

### Build flavors (optional eBPF attribution)

Two flavors, one make target each:

```bash
make build        # default binary: /proc-based attribution, no extra toolchain
make build-ebpf   # hybrid binary: eBPF fills a 5-tuple->PID map, /proc as fallback
```

`make build-ebpf` chains header vendoring, `vmlinux.h` generation, and bpf2go
codegen; it needs a one-time toolchain (`clang`, `llvm-strip`, `bpftool`, libbpf
CO-RE headers). The eBPF loader sits behind the `ebpf_generated` build tag; the
default build compiles a stub, so plain `go build`/`go vet`/`go test` never need
the toolchain. bpf2go output (`attribute_bpfel.{go,o}`) and `vmlinux.h` are
gitignored — regenerate with `make build-ebpf`. `make help` lists all targets.

If the distro `bpftool` is a kernel-version wrapper not installed for the
running kernel, point make at any working one (any recent bpftool can dump the
running kernel's BTF): `make build-ebpf BPFTOOL=/path/to/bpftool`.

## Run

Needs root (AF_PACKET socket + reading other processes' `/proc/<pid>/fd`):

```bash
sudo ./procnet                 # auto-detects the default-route interface
sudo ./procnet -i wlp0s20f3    # explicit interface
sudo ./procnet --no-tui        # headless: periodic totals to stdout
sudo ./procnet --out totals.json   # write per-process totals on exit
```

Flags: `-i <iface>`, `--out <path>` (.json/.csv), `--no-tui`, `--log-interval <dur>`,
`--ebpf <auto|on|off>` (default `auto`: use eBPF if available, else /proc),
`--debug-unknown <path>` (log every unattributed packet with its miss reason).
TUI keys: `q` quit, `s` toggle sort (total⇄rate), `r` reset, `p` pause.

## Architecture

Data flows: capture → resolve PID → aggregate → display/export.

- `cmd/procnet` — flag parsing, wiring, `signal.NotifyContext` for clean
  shutdown (cancel → TUI/headless stop → export).
- `internal/capture` — `PacketSource` interface; `afpacket_linux.go` uses
  `pcapgo.NewEthernetHandle` (pure-Go AF_PACKET, no libpcap-dev/cgo) and a
  `gopacket` `DecodingLayerParser`. Direction is decided by comparing src/dst
  against the interface's local addresses. **Byte count uses the kernel AUXDATA
  original length (`ci.Length`), not the captured slice** — keep this so counts
  stay correct even when the capture buffer truncates.
- `internal/procmap` — parses `/proc/net/{tcp,tcp6,udp,udp6}` (addresses are
  little-endian hex per 32-bit word, ports hex; covered by fixture tests in
  `parse_test.go` — don't regress the byte order). `inode.go` walks
  `/proc/*/fd/*` for `socket:[inode]`. `resolver.go` caches inode→PID (~1s
  refresh) plus a TTL 5-tuple→PID cache so short-lived flows still attribute. On
  a miss it re-reads `/proc/net` on demand and does a targeted single-inode fd
  scan, negative-caching failures briefly. If a `FlowResolver` is installed via
  `SetFlowResolver` (see `internal/ebpf`), `Lookup` consults it first, then the
  /proc path. `DefaultInterface()` reads `/proc/net/route` (Destination=0).
  Unattributable packets go to the `unknown` bucket.
- `internal/ebpf` — optional, behind the `ebpf_generated` build tag. A CO-RE
  eBPF program (fentry on `tcp_sendmsg`/`udp_sendmsg`, `bpf/attribute.bpf.c`)
  fills a 5-tuple→{pid,comm} LRU map in-kernel at send time; `source.go` loads
  it via cilium/ebpf and implements `procmap.FlowResolver`, so a flow is
  attributable from its first packet. The default build uses `source_stub.go`
  (`NewSource` returns "not built"), so eBPF is fully optional. `procmap` never
  imports this package — the `FlowResolver` interface is the one-way boundary.
- `internal/aggregate` — per-PID counters; rate = delta/interval smoothed with
  EWMA (α=0.3); cumulative totals; `Snapshot` sorted desc.
- `internal/ui` — bubbletea + bubbles/table; `Run(ctx, ...)`; 1s tick.
- `internal/export` — JSON/CSV via `ToFile` (extension-based), `RunHeadless`.

## Conventions

- Standard library for `/proc` parsing — avoid heavy deps.
- Every package that parses external formats (`/proc`, packets) needs unit tests
  with inline fixtures; run `go test ./...` before considering a change done.
- Counting semantics = on-wire bytes (headers + retransmits), because the goal
  is matching carrier-billed data. Don't switch to socket-payload accounting.

## Known limitations

- Short flows outside the TTL window, and traffic from processes not visible in
  this network namespace, fall into `unknown`.
- Containers in a separate netns sharing the physical link won't attribute
  correctly.
- eBPF attribution covers IPv4 connected sockets only; IPv6 and unconnected UDP
  (`sendto`) fall back to /proc, and kernels without BTF (or run without the
  needed privilege) fall back to /proc entirely.
