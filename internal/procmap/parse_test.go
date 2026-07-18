package procmap

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

func TestParseHexAddrIPv4(t *testing.T) {
	// "0100007F" is the little-endian-per-word encoding of 127.0.0.1.
	ip, err := parseHexAddr("0100007F")
	if err != nil {
		t.Fatalf("parseHexAddr: %v", err)
	}
	if got, want := ip.String(), "127.0.0.1"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestParseHexAddrIPv4NonLoopback(t *testing.T) {
	// 192.168.1.5 -> bytes C0 A8 01 05 -> word-reversed hex "050 1A8C0"... compute directly.
	ip := net.ParseIP("192.168.1.5").To4()
	hexStr := ""
	for i := 3; i >= 0; i-- {
		hexStr += byteToHex(ip[i])
	}
	got, err := parseHexAddr(hexStr)
	if err != nil {
		t.Fatalf("parseHexAddr: %v", err)
	}
	if got.String() != "192.168.1.5" {
		t.Errorf("got %s, want 192.168.1.5", got.String())
	}
}

func byteToHex(b byte) string {
	const hexDigits = "0123456789ABCDEF"
	return string([]byte{hexDigits[b>>4], hexDigits[b&0xF]})
}

func TestParseHexAddrIPv6Loopback(t *testing.T) {
	// ::1 encoded as four little-endian 32-bit words (32 hex chars, 16 bytes),
	// as it actually appears in /proc/net/tcp6.
	got, err := parseHexAddr("00000000000000000000000001000000")
	if err != nil {
		t.Fatalf("parseHexAddr: %v", err)
	}
	if got.String() != "::1" {
		t.Errorf("got %s, want ::1", got.String())
	}
}

func TestParseHexPort(t *testing.T) {
	port, err := parseHexPort("44C0")
	if err != nil {
		t.Fatalf("parseHexPort: %v", err)
	}
	if port != 17600 {
		t.Errorf("got %d, want 17600", port)
	}
}

func TestParseAddrPort(t *testing.T) {
	ip, port, err := parseAddrPort("0100007F:1F90")
	if err != nil {
		t.Fatalf("parseAddrPort: %v", err)
	}
	if ip.String() != "127.0.0.1" || port != 8080 {
		t.Errorf("got %s:%d, want 127.0.0.1:8080", ip, port)
	}
}

// fixtureTCP mirrors the real /proc/net/tcp format (header + entries),
// including the header line which must be skipped.
const fixtureTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:44C0 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 16314 1 0000000000000000 100 0 0 10 0
   1: 0500A8C0:C001 0800A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 99999 1 0000000000000000 100 0 0 10 0
`

func TestParseNetFile(t *testing.T) {
	entries := parseNetFile(bufio.NewScanner(strings.NewReader(fixtureTCP)))
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}

	// Row 0: listening socket on 127.0.0.1:17600, inode 16314.
	if entries[0].LocalIP.String() != "127.0.0.1" {
		t.Errorf("entry0 local IP = %s, want 127.0.0.1", entries[0].LocalIP)
	}
	if entries[0].Local != 17600 {
		t.Errorf("entry0 local port = %d, want 17600", entries[0].Local)
	}
	if entries[0].Inode != 16314 {
		t.Errorf("entry0 inode = %d, want 16314", entries[0].Inode)
	}

	// Row 1: established connection 192.168.0.5:49153 -> 192.168.0.8:443, inode 99999.
	if entries[1].LocalIP.String() != "192.168.0.5" {
		t.Errorf("entry1 local IP = %s, want 192.168.0.5", entries[1].LocalIP)
	}
	if entries[1].Local != 49153 {
		t.Errorf("entry1 local port = %d, want 49153", entries[1].Local)
	}
	if entries[1].RemoteIP.String() != "192.168.0.8" {
		t.Errorf("entry1 remote IP = %s, want 192.168.0.8", entries[1].RemoteIP)
	}
	if entries[1].Remote != 443 {
		t.Errorf("entry1 remote port = %d, want 443", entries[1].Remote)
	}
	if entries[1].Inode != 99999 {
		t.Errorf("entry1 inode = %d, want 99999", entries[1].Inode)
	}
}

func TestParseSocketLink(t *testing.T) {
	cases := []struct {
		link    string
		wantOK  bool
		wantVal uint64
	}{
		{"socket:[12345]", true, 12345},
		{"anon_inode:[eventpoll]", false, 0},
		{"/dev/pts/3", false, 0},
		{"socket:[0]", true, 0},
	}
	for _, c := range cases {
		got, ok := parseSocketLink(c.link)
		if ok != c.wantOK || (ok && got != c.wantVal) {
			t.Errorf("parseSocketLink(%q) = (%d, %v), want (%d, %v)", c.link, got, ok, c.wantVal, c.wantOK)
		}
	}
}
