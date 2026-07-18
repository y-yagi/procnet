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

## Run

Needs root (AF_PACKET socket + reading other processes' `/proc/<pid>/fd`):

```bash
sudo ./procnet                 # auto-detects the default-route interface
sudo ./procnet -i wlp0s20f3    # explicit interface
sudo ./procnet --no-tui        # headless: periodic totals to stdout
sudo ./procnet --out totals.json   # write per-process totals on exit
```

Flags: `-i <iface>`, `--out <path>` (.json/.csv), `--no-tui`, `--log-interval <dur>`.
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
  refresh) plus a TTL 5-tuple→PID cache so short-lived flows still attribute.
  `DefaultInterface()` reads `/proc/net/route` (Destination=0). Unattributable
  packets go to the `unknown` bucket.
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
