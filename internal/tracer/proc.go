package tracer

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procInfo holds data collected from /proc/[pid]/
type procInfo struct {
	exe      string
	cwd      string
	memoryKB int
	fdCount  int
}

// enrichFromProc reads /proc/[pid]/ immediately after the kernel event arrives.
// The process may be short-lived, so we do this as fast as possible.
func enrichFromProc(pid uint32) procInfo {
	base := fmt.Sprintf("/proc/%d", pid)
	info := procInfo{}

	// /proc/[pid]/exe — the resolved real path of the executable
	if exe, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		info.exe = exe
	}

	// /proc/[pid]/cwd — the current working directory
	if cwd, err := os.Readlink(filepath.Join(base, "cwd")); err == nil {
		info.cwd = cwd
	}

	// /proc/[pid]/status — memory usage
	if f, err := os.Open(filepath.Join(base, "status")); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "VmRSS:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					info.memoryKB, _ = strconv.Atoi(fields[1])
				}
			}
		}
	}

	// /proc/[pid]/fd — count of open file descriptors
	if entries, err := os.ReadDir(filepath.Join(base, "fd")); err == nil {
		info.fdCount = len(entries)
	}

	return info
}
