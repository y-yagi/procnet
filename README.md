# procnet

Real-time, per-process network transfer volume for Linux — like `nethogs`,
but built for tracking mobile-data usage over a tethered connection.

It captures raw packets on a chosen interface, attributes each one to the
local process that sent/received it (via `/proc`), and shows a live table of
sent/received/total bytes plus rate, per process. Because it counts actual
on-wire bytes (including TCP/IP headers and retransmits) via packet capture
rather than sampling socket-layer writes, the numbers line up with what a
carrier's data meter would count.

## Why packet capture

An eBPF socket-layer hook (e.g. `tcp_sendmsg`) only sees payload bytes and
undercounts headers and retransmissions. Packet capture on the wire sees the
actual bytes that went over the link, which is what matters for a metered
connection.

## Usage

```sh
go build -o procnet ./cmd/procnet

# Monitor a specific interface (e.g. your phone tethered as usb0):
sudo ./procnet -i usb0

# Auto-detect the current default-route interface (useful right after your
# phone becomes the default route via tethering):
sudo ./procnet

# Headless logging instead of the TUI, e.g. for unattended background runs:
sudo ./procnet -i usb0 --no-tui --log-interval 10s

# Write final per-process totals on exit:
sudo ./procnet -i usb0 --out totals.json
sudo ./procnet -i usb0 --out totals.csv
```

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `-i` | auto (default route interface) | Interface to capture on |
| `--out` | (none) | Write final per-process totals here on exit (`.json` or `.csv`) |
| `--no-tui` | false | Headless mode: print a periodic summary line instead of the TUI |
| `--log-interval` | 5s | How often `--no-tui` prints a summary line |

### TUI keys

| Key | Action |
|---|---|
| `q` / `ctrl+c` / `esc` | Quit (writes `--out` if given) |
| `s` | Toggle sort: total bytes / current rate |
| `r` | Reset all counters |
| `p` | Pause/resume the display (capture keeps running underneath) |

`SIGINT`/`SIGTERM` (e.g. `kill`, or Ctrl+C caught outside the TUI's raw
terminal mode) trigger the same clean shutdown-and-export path.

## Permissions

Capturing requires an `AF_PACKET` raw socket (`CAP_NET_RAW`), and process
attribution requires reading other processes' `/proc/<pid>/fd/*` entries
(effectively root in most configurations). Two ways to run:

```sh
sudo ./procnet -i usb0
```

or grant the binary just the capabilities it needs and run unprivileged:

```sh
sudo setcap cap_net_raw,cap_dac_read_search+ep ./procnet
./procnet -i usb0
```

Note that with `setcap`, reading `/proc/<other-pid>/fd/*` for processes
owned by *other users* may still be restricted by the kernel depending on
`/proc/sys/kernel/yama/ptrace_scope` and similar hardening; running under
`sudo` is the more reliable option.

## How it works

- **Capture** (`internal/capture`): opens an `AF_PACKET` socket via
  `gopacket/pcapgo` (pure Go, no `libpcap-dev` needed) and decodes
  Ethernet/IPv4/IPv6/TCP/UDP headers. A packet's byte count is its captured
  on-wire frame length. Direction (sent vs. received) is determined by
  comparing source/destination IP against the monitored interface's local
  addresses.
- **Process mapping** (`internal/procmap`): parses `/proc/net/{tcp,tcp6,udp,udp6}`
  (hex-encoded addresses/ports/inode) to map local sockets to inodes, and
  walks `/proc/*/fd/*` to map inodes to PIDs — the same technique `nethogs`
  uses. Both tables are cached and refreshed roughly once a second; resolved
  5-tuple → PID mappings are kept for a few seconds past that so short-lived
  connections aren't lost to `unknown` once their socket disappears from
  `/proc/net`.
- **Aggregation** (`internal/aggregate`): per-PID cumulative sent/received
  byte counters, plus an EWMA-smoothed instantaneous rate recomputed once a
  second.
- **UI** (`internal/ui`): a `bubbletea`/`bubbles/table` TUI, sorted by total
  bytes (or rate) descending, refreshed once a second.
- **Export** (`internal/export`): JSON/CSV dump of final per-process totals,
  and a headless periodic-summary mode for `--no-tui`.

## Limitations

- Linux only (uses `AF_PACKET` and `/proc`).
- Traffic that can't be matched to a local process (very short-lived flows
  outside the TTL window, or flows from processes/namespaces `/proc` can't
  see) is bucketed under `unknown`.
- Per-process attribution assumes traffic on the monitored interface belongs
  to a socket visible in this network namespace's `/proc/net`; containerized
  processes in a different network namespace sharing the same physical link
  (e.g. via a bridge) will not resolve correctly.
- Promiscuous mode is enabled on the capture interface; on some virtual
  interfaces (e.g. certain USB tethering drivers) that may be a no-op or
  unsupported — capture of the host's own traffic still works either way
  since it doesn't require promiscuous mode.
- Byte counts include full on-wire frames (L2 header, IP/TCP/UDP headers,
  retransmissions) by design, so totals will exceed applications' reported
  payload sizes and will exceed `/proc/net/dev` payload-only counters
  slightly less but track them closely; compare against `/proc/net/dev`
  deltas for a sanity check.
- Requires root (or `cap_net_raw,cap_dac_read_search`) to run at all; see
  Permissions above.
