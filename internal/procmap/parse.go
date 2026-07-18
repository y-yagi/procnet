// Package procmap resolves network packets to the local process that owns
// them by parsing Linux's /proc filesystem, the same technique nethogs uses.
//
// Two lookups are combined:
//   - /proc/net/{tcp,tcp6,udp,udp6} maps a local socket (address:port) to an
//     inode number.
//   - /proc/<pid>/fd/* symlinks of the form "socket:[<inode>]" map that
//     inode to the owning PID.
//
// Both are expensive to rebuild (especially the fd walk across all
// processes), so callers should use Resolver, which caches both layers.
package procmap

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Proto identifies which /proc/net/* table a socket was found in.
type Proto int

const (
	ProtoTCP Proto = iota
	ProtoUDP
)

// SocketKey identifies a local socket endpoint as found in /proc/net.
type SocketKey struct {
	Proto     Proto
	LocalIP   string // net.IP.String() form
	LocalPort uint16
}

// parseHexAddr decodes the address portion of a /proc/net/{tcp,udp}[6] entry
// (e.g. "0100007F" or "00000000000000000000000001000000") into a net.IP.
//
// The kernel writes the address as a sequence of 32-bit words in host byte
// order; on the little-endian x86/ARM systems this tool targets that means
// each 4-byte (8 hex char) group has its bytes reversed relative to network
// order. IPv4 addresses are one word (4 bytes); IPv6 addresses are four
// words (16 bytes total).
func parseHexAddr(s string) (net.IP, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("procmap: decode address %q: %w", s, err)
	}
	if len(raw)%4 != 0 || len(raw) == 0 {
		return nil, fmt.Errorf("procmap: address %q has unexpected length %d", s, len(raw))
	}
	out := make([]byte, len(raw))
	for word := 0; word < len(raw); word += 4 {
		out[word+0] = raw[word+3]
		out[word+1] = raw[word+2]
		out[word+2] = raw[word+1]
		out[word+3] = raw[word+0]
	}
	return net.IP(out), nil
}

// parseHexPort decodes a port field (e.g. "44C0") which is stored in
// network byte order (no reversal needed, unlike the address).
func parseHexPort(s string) (uint16, error) {
	v, err := strconv.ParseUint(s, 16, 16)
	if err != nil {
		return 0, fmt.Errorf("procmap: decode port %q: %w", s, err)
	}
	return uint16(v), nil
}

// parseAddrPort splits and decodes a "HEXADDR:HEXPORT" field.
func parseAddrPort(field string) (net.IP, uint16, error) {
	idx := strings.LastIndexByte(field, ':')
	if idx < 0 {
		return nil, 0, fmt.Errorf("procmap: malformed addr:port %q", field)
	}
	ip, err := parseHexAddr(field[:idx])
	if err != nil {
		return nil, 0, err
	}
	port, err := parseHexPort(field[idx+1:])
	if err != nil {
		return nil, 0, err
	}
	return ip, port, nil
}

// entry is one parsed row of /proc/net/{tcp,udp}[6].
type entry struct {
	LocalIP  net.IP
	Local    uint16
	RemoteIP net.IP
	Remote   uint16
	Inode    uint64
}

// parseNetFile parses the body of a /proc/net/{tcp,tcp6,udp,udp6} file.
// The first line (header) is skipped. Malformed lines are skipped rather
// than aborting the whole parse, since a transient read mid-line-change is
// possible on a live /proc file.
func parseNetFile(r *bufio.Scanner) []entry {
	var entries []entry
	first := true
	for r.Scan() {
		line := strings.TrimSpace(r.Text())
		if first {
			first = false
			continue // header
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		localIP, localPort, err := parseAddrPort(fields[1])
		if err != nil {
			continue
		}
		remoteIP, remotePort, err := parseAddrPort(fields[2])
		if err != nil {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		entries = append(entries, entry{
			LocalIP:  localIP,
			Local:    localPort,
			RemoteIP: remoteIP,
			Remote:   remotePort,
			Inode:    inode,
		})
	}
	return entries
}

// readNetFile parses a real /proc/net/* file by path. Missing files (e.g.
// tcp6/udp6 when IPv6 is disabled) are treated as empty, not an error.
func readNetFile(path string) ([]entry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	return parseNetFile(bufio.NewScanner(f)), nil
}
