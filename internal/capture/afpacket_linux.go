//go:build linux

package capture

import (
	"fmt"
	"net"
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// AFPacketSource captures raw Ethernet frames from a network interface using
// an AF_PACKET socket (via pcapgo.EthernetHandle, pure Go, no libpcap
// dependency) and decodes L3/L4 headers to produce Packet values.
type AFPacketSource struct {
	handle    *pcapgo.EthernetHandle
	local     map[string]struct{} // local IP addresses of the monitored interface, keyed by String()
	out       chan Packet
	closeOnce sync.Once
	done      chan struct{}
}

// NewAFPacketSource opens an AF_PACKET capture on ifaceName in promiscuous
// mode and starts decoding packets in a background goroutine.
func NewAFPacketSource(ifaceName string) (*AFPacketSource, error) {
	handle, err := pcapgo.NewEthernetHandle(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("capture: open %s: %w", ifaceName, err)
	}
	// Use a generous capture buffer so we rarely truncate frames; byte
	// accounting itself relies on the original (pre-truncation) length
	// reported by the kernel via AUXDATA, not the captured slice length.
	if err := handle.SetCaptureLength(65536); err != nil {
		handle.Close()
		return nil, fmt.Errorf("capture: set capture length: %w", err)
	}
	if err := handle.SetPromiscuous(true); err != nil {
		handle.Close()
		return nil, fmt.Errorf("capture: set promiscuous: %w", err)
	}

	local, err := localAddresses(ifaceName)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("capture: local addresses: %w", err)
	}

	s := &AFPacketSource{
		handle: handle,
		local:  local,
		out:    make(chan Packet, 1024),
		done:   make(chan struct{}),
	}
	go s.loop()
	return s, nil
}

// localAddresses returns the set of IP addresses (IPv4/IPv6) configured on
// the named interface, used for direction determination.
func localAddresses(ifaceName string) (map[string]struct{}, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		set[ipNet.IP.String()] = struct{}{}
	}
	return set, nil
}

func (s *AFPacketSource) loop() {
	defer close(s.out)

	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	decoded := make([]gopacket.LayerType, 0, 4)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp)
	parser.IgnoreUnsupported = true

	for {
		select {
		case <-s.done:
			return
		default:
		}

		data, ci, err := s.handle.ZeroCopyReadPacketData()
		if err != nil {
			// EAGAIN/temporary errors are expected on a non-blocking socket;
			// just keep polling. A closed handle will error persistently,
			// but s.done is checked each iteration so Close() still exits us.
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}

		if err := parser.DecodeLayers(data, &decoded); err != nil {
			// Unsupported/malformed layers below IPv4/IPv6 are common
			// (ARP, STP, etc.) - just skip them.
			continue
		}

		pkt := Packet{Length: ci.Length}
		if pkt.Length == 0 {
			pkt.Length = len(data)
		}

		haveL3 := false
		for _, lt := range decoded {
			switch lt {
			case layers.LayerTypeIPv4:
				pkt.SrcIP = ip4.SrcIP
				pkt.DstIP = ip4.DstIP
				haveL3 = true
			case layers.LayerTypeIPv6:
				pkt.SrcIP = ip6.SrcIP
				pkt.DstIP = ip6.DstIP
				haveL3 = true
			case layers.LayerTypeTCP:
				pkt.Proto = ProtoTCP
				pkt.SrcPort = uint16(tcp.SrcPort)
				pkt.DstPort = uint16(tcp.DstPort)
			case layers.LayerTypeUDP:
				pkt.Proto = ProtoUDP
				pkt.SrcPort = uint16(udp.SrcPort)
				pkt.DstPort = uint16(udp.DstPort)
			}
		}
		if !haveL3 {
			continue
		}

		pkt.Direction = s.direction(pkt.SrcIP, pkt.DstIP)

		select {
		case s.out <- pkt:
		case <-s.done:
			return
		}
	}
}

// direction determines whether a packet is outbound (local source) or
// inbound (local destination) relative to the monitored interface's
// addresses. If neither side matches, DirUnknown is returned.
func (s *AFPacketSource) direction(src, dst net.IP) Direction {
	if _, ok := s.local[src.String()]; ok {
		return DirOutbound
	}
	if _, ok := s.local[dst.String()]; ok {
		return DirInbound
	}
	return DirUnknown
}

// Packets implements PacketSource.
func (s *AFPacketSource) Packets() <-chan Packet {
	return s.out
}

// Close implements PacketSource.
func (s *AFPacketSource) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
	})
	return s.handle.Close()
}
