package procmap

import (
	"os"
	"strconv"
	"strings"
)

// buildInodeToPID walks /proc/<pid>/fd/* for every process and returns a map
// of socket inode -> owning PID. This is the expensive walk that Resolver
// caches; it requires read access to other users' /proc/<pid>/fd entries,
// i.e. running as root (or with CAP_DAC_READ_SEARCH).
func buildInodeToPID() (map[uint64]int, error) {
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	result := make(map[uint64]int)
	for _, pe := range procEntries {
		pid, err := strconv.Atoi(pe.Name())
		if err != nil {
			continue // not a PID directory
		}
		fdDir := "/proc/" + pe.Name() + "/fd"
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			// Process exited or we lack permission; skip silently.
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(fdDir + "/" + fd.Name())
			if err != nil {
				continue
			}
			inode, ok := parseSocketLink(link)
			if !ok {
				continue
			}
			result[inode] = pid
		}
	}
	return result, nil
}

// parseSocketLink extracts the inode from a symlink target of the form
// "socket:[12345]". Non-socket links return ok=false.
func parseSocketLink(link string) (inode uint64, ok bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(link, prefix) || !strings.HasSuffix(link, "]") {
		return 0, false
	}
	num := link[len(prefix) : len(link)-1]
	v, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// processName returns the short command name for pid, as reported by
// /proc/<pid>/comm (truncated to 15 chars by the kernel). Returns "" if it
// cannot be read (process may have exited).
func processName(pid int) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
