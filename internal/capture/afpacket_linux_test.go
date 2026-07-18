//go:build linux

package capture

import (
	"net"
	"testing"
)

func TestDirection(t *testing.T) {
	s := &AFPacketSource{
		local: map[string]struct{}{
			"192.168.1.5": {},
			"fe80::1":     {},
		},
	}

	cases := []struct {
		name string
		src  string
		dst  string
		want Direction
	}{
		{"outbound v4", "192.168.1.5", "93.184.216.34", DirOutbound},
		{"inbound v4", "93.184.216.34", "192.168.1.5", DirInbound},
		{"outbound v6", "fe80::1", "2001:db8::1", DirOutbound},
		{"inbound v6", "2001:db8::1", "fe80::1", DirInbound},
		{"neither local", "10.0.0.1", "10.0.0.2", DirUnknown},
		// If both happen to match (e.g. loopback-to-self), outbound wins
		// since src is checked first.
		{"both local", "192.168.1.5", "192.168.1.5", DirOutbound},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := s.direction(net.ParseIP(c.src), net.ParseIP(c.dst))
			if got != c.want {
				t.Errorf("direction(%s -> %s) = %v, want %v", c.src, c.dst, got, c.want)
			}
		})
	}
}
