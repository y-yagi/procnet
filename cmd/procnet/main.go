// Command procnet shows real-time, per-process network transfer volume on
// Linux by capturing packets on a chosen interface (default: the interface
// of the current default route) and attributing them to the owning process
// via /proc.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/y-yagi/procnet/internal/aggregate"
	"github.com/y-yagi/procnet/internal/capture"
	"github.com/y-yagi/procnet/internal/ebpf"
	"github.com/y-yagi/procnet/internal/export"
	"github.com/y-yagi/procnet/internal/procmap"
	"github.com/y-yagi/procnet/internal/ui"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "procnet:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		iface    = flag.String("i", "", "network interface to monitor (default: current default-route interface)")
		out      = flag.String("out", "", "write final per-process totals to this file on exit (.json or .csv)")
		noTUI    = flag.Bool("no-tui", false, "headless mode: periodically print totals to stdout instead of the TUI")
		logInt   = flag.Duration("log-interval", 5*time.Second, "how often to print a summary line in -no-tui mode")
		dbgUnk   = flag.String("debug-unknown", "", "log every unattributed (\"unknown\") packet to this file: reason, proto, direction, src->dst, bytes")
		ebpfMode = flag.String("ebpf", "auto", "eBPF-based attribution: auto (use if available, default), on (fail if unavailable), off (/proc only)")
	)
	flag.Parse()

	switch *ebpfMode {
	case "auto", "on", "off":
	default:
		return fmt.Errorf("invalid -ebpf value %q: must be auto, on, or off", *ebpfMode)
	}

	ifaceName := *iface
	if ifaceName == "" {
		det, err := procmap.DefaultInterface()
		if err != nil {
			return fmt.Errorf("no -i given and could not auto-detect default-route interface: %w", err)
		}
		ifaceName = det
	}

	src, err := capture.NewAFPacketSource(ifaceName)
	if err != nil {
		return fmt.Errorf("starting capture on %s (are you root, or did you setcap the binary?): %w", ifaceName, err)
	}
	defer src.Close()

	var dbg *unknownLogger
	if *dbgUnk != "" {
		f, err := os.Create(*dbgUnk)
		if err != nil {
			return fmt.Errorf("opening -debug-unknown file %s: %w", *dbgUnk, err)
		}
		defer f.Close()
		dbg = &unknownLogger{l: log.New(f, "", log.LstdFlags|log.Lmicroseconds)}
	}

	agg := aggregate.New()
	resolver := procmap.NewResolver()

	if *ebpfMode != "off" {
		es, err := ebpf.NewSource()
		if err != nil {
			if *ebpfMode == "on" {
				return fmt.Errorf("eBPF requested (-ebpf=on) but unavailable: %w", err)
			}
			fmt.Fprintln(os.Stderr, "procnet: eBPF unavailable, falling back to /proc attribution:", err)
		} else {
			resolver.SetFlowResolver(es)
			defer es.Close()
		}
	}

	go pump(src, resolver, agg, dbg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var runErr error
	if *noTUI {
		export.RunHeadless(os.Stdout, agg, ifaceName, *logInt, ctx.Done())
	} else {
		runErr = ui.Run(ctx, agg, ifaceName)
	}

	if *out != "" {
		if exportErr := export.ToFile(*out, agg.Snapshot()); exportErr != nil {
			fmt.Fprintln(os.Stderr, "procnet: export failed:", exportErr)
		} else {
			fmt.Fprintln(os.Stderr, "procnet: wrote totals to", *out)
		}
	}

	return runErr
}

// pump reads decoded packets from src, resolves each to an owning process
// via resolver, and feeds the byte counts into agg. It returns when src's
// channel closes (i.e. after Close()).
func pump(src capture.PacketSource, resolver *procmap.Resolver, agg *aggregate.Aggregator, dbg *unknownLogger) {
	for pkt := range src.Packets() {
		if pkt.Proto == capture.ProtoUnknown {
			dbg.log("proto-unknown", pkt)
			agg.AddRecv(aggregate.UnknownPID, aggregate.UnknownName, uint64(pkt.Length))
			continue
		}
		if pkt.Direction == capture.DirUnknown {
			dbg.log("direction-unknown", pkt)
			agg.AddRecv(aggregate.UnknownPID, aggregate.UnknownName, uint64(pkt.Length))
			continue
		}

		proto := procmap.ProtoTCP
		if pkt.Proto == capture.ProtoUDP {
			proto = procmap.ProtoUDP
		}

		localIP, remoteIP := pkt.SrcIP, pkt.DstIP
		localPort, remotePort := pkt.SrcPort, pkt.DstPort
		if pkt.Direction == capture.DirInbound {
			localIP, remoteIP = pkt.DstIP, pkt.SrcIP
			localPort, remotePort = pkt.DstPort, pkt.SrcPort
		}

		pid, name, ok := resolver.Lookup(proto, localIP, localPort, remoteIP, remotePort)
		if !ok {
			dbg.log("lookup-miss", pkt)
			pid, name = aggregate.UnknownPID, aggregate.UnknownName
		}

		switch pkt.Direction {
		case capture.DirOutbound:
			agg.AddSent(pid, name, uint64(pkt.Length))
		case capture.DirInbound:
			agg.AddRecv(pid, name, uint64(pkt.Length))
		}
	}
}

// unknownLogger writes one line per unattributed packet to a file, so the
// contents of the "unknown" bucket can be inspected without disturbing the
// TUI (which owns stdout/stderr).
type unknownLogger struct {
	l *log.Logger
}

// log records a single unknown packet. A nil receiver is a no-op, so callers
// can pass a nil *unknownLogger when -debug-unknown is not set.
func (u *unknownLogger) log(reason string, pkt capture.Packet) {
	if u == nil {
		return
	}
	u.l.Printf("reason=%s proto=%s dir=%s %s -> %s len=%d",
		reason, protoName(pkt.Proto), dirName(pkt.Direction),
		hostPort(pkt.SrcIP, pkt.SrcPort), hostPort(pkt.DstIP, pkt.DstPort), pkt.Length)
}

func protoName(p capture.Proto) string {
	switch p {
	case capture.ProtoTCP:
		return "tcp"
	case capture.ProtoUDP:
		return "udp"
	default:
		return "unknown"
	}
}

func dirName(d capture.Direction) string {
	switch d {
	case capture.DirOutbound:
		return "out"
	case capture.DirInbound:
		return "in"
	default:
		return "unknown"
	}
}

func hostPort(ip net.IP, port uint16) string {
	if ip == nil {
		return fmt.Sprintf("?:%d", port)
	}
	return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
}
