// Command procnet shows real-time, per-process network transfer volume on
// Linux by capturing packets on a chosen interface (default: the interface
// of the current default route) and attributing them to the owning process
// via /proc.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/y-yagi/procnet/internal/aggregate"
	"github.com/y-yagi/procnet/internal/capture"
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
		iface  = flag.String("i", "", "network interface to monitor (default: current default-route interface)")
		out    = flag.String("out", "", "write final per-process totals to this file on exit (.json or .csv)")
		noTUI  = flag.Bool("no-tui", false, "headless mode: periodically print totals to stdout instead of the TUI")
		logInt = flag.Duration("log-interval", 5*time.Second, "how often to print a summary line in -no-tui mode")
	)
	flag.Parse()

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

	agg := aggregate.New()
	resolver := procmap.NewResolver()
	go pump(src, resolver, agg)

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
func pump(src capture.PacketSource, resolver *procmap.Resolver, agg *aggregate.Aggregator) {
	for pkt := range src.Packets() {
		if pkt.Direction == capture.DirUnknown || pkt.Proto == capture.ProtoUnknown {
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
