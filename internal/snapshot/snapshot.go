package snapshot

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type SnapshotEngine struct {
	procPath string
}

func NewSnapshotEngine(optProcPath string) *SnapshotEngine {
	if optProcPath == "" {
		optProcPath = "/proc"
	}
	return &SnapshotEngine{
		procPath: optProcPath,
	}
}

func (s *SnapshotEngine) Build() (*SnapshotJSON, error) {
	btime := s.getSystemBootTime()

	entries, err := os.ReadDir(s.procPath)
	if err != nil {
		return nil, err
	}

	processes := make(map[uint32]*ProcessInfo)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		pidPath := filepath.Join(s.procPath, entry.Name())

		ppid, name := s.parseStatusFile(filepath.Join(pidPath, "status"))

		cmdline := s.parseCmdlineFile(filepath.Join(pidPath, "cmdline"))
		if cmdline == "" {
			cmdline = name
		}

		startTime := s.parseStartTime(filepath.Join(pidPath, "stat"), btime)

		processes[uint32(pid)] = &ProcessInfo{
			PID:       uint32(pid),
			PPID:      ppid,
			Command:   cmdline,
			Status:    "alive",
			Source:    SourceSnapshot,
			StartTime: startTime,
		}
	}

	return &SnapshotJSON{
		Type:      "snapshot",
		Processes: processes,
	}, nil
}

func (s *SnapshotEngine) getSystemBootTime() time.Time {
	data, err := os.ReadFile(filepath.Join(s.procPath, "stat"))
	if err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "btime ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if sec, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
						return time.Unix(sec, 0)
					}
				}
			}
		}
	}
	return time.Now().Add(-1 * time.Hour)
}

func (s *SnapshotEngine) parseStatusFile(path string) (uint32, string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, ""
	}

	var ppid uint32
	var name string

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Name:\t") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "Name:\t"))
		} else if strings.HasPrefix(line, "PPid:\t") {
			if val, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "PPid:\t")), 10, 32); err == nil {
				ppid = uint32(val)
			}
		}
	}
	return ppid, name
}

func (s *SnapshotEngine) parseCmdlineFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return ""
	}
	data = bytes.ReplaceAll(data, []byte{0}, []byte{' '})
	return strings.TrimSpace(string(data))
}

func (s *SnapshotEngine) parseStartTime(path string, btime time.Time) time.Time {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Now()
	}

	str := string(data)
	idx := strings.LastIndex(str, ")")
	if idx != -1 && idx+2 < len(str) {
		str = str[idx+2:]
	}

	fields := strings.Fields(str)
	if len(fields) >= 20 {
		if ticks, err := strconv.ParseUint(fields[19], 10, 64); err == nil {
			secsSinceBoot := int64(ticks / 100)
			return btime.Add(time.Duration(secsSinceBoot) * time.Second)
		}
	}
	return time.Now()
}
