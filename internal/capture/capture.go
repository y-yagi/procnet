// Package capture provides packet capture and per-packet L3/L4 decoding for
// procnet. It abstracts the underlying capture mechanism behind the
// PacketSource interface so that AF_PACKET (default, pure Go) can later be
// swapped for a libpcap-based implementation if needed.
package capture

import "net"

// Direction indicates whether a captured packet was sent from or received by
// the local interface being monitored.
type Direction int

const (
	// DirUnknown means the packet's direction could not be determined
	// relative to the monitored interface's local addresses.
	DirUnknown Direction = iota
	// DirOutbound means the packet's source address is local (sent).
	DirOutbound
	// DirInbound means the packet's destination address is local (received).
	DirInbound
)

// Proto identifies the L4 transport protocol of a captured packet.
type Proto int

const (
	ProtoUnknown Proto = iota
	ProtoTCP
	ProtoUDP
)

// Packet is a decoded summary of a single captured frame, sufficient for
// process attribution (via 5-tuple) and byte accounting.
type Packet struct {
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Proto     Proto
	Direction Direction
	Length    int // on-wire frame length in bytes, as captured (includes L2/L3/L4 headers)
}

// PacketSource produces a stream of decoded packets from a live capture.
// Implementations must be safe to call Close concurrently with Packets.
type PacketSource interface {
	// Packets returns a channel of decoded packets. The channel is closed
	// when the source is closed or encounters a fatal error.
	Packets() <-chan Packet
	// Close stops the capture and releases underlying resources.
	Close() error
}
