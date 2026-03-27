package models

import (
	"fmt"
	"strings"
)

type EventJSON struct {
	Type     string `json:"type"`
	PID      uint32 `json:"pid"`
	PPID     uint32 `json:"ppid,omitempty"`
	UID      uint32 `json:"uid"`
	GID      uint32 `json:"gid"`
	CgroupID uint64 `json:"cgroup_id,omitempty"`
	Command  string `json:"command"`
	Path     string `json:"path,omitempty"`
	Exe      string `json:"exe,omitempty"`
	CWD      string `json:"cwd,omitempty"`
	MemoryKB int    `json:"memory_kb,omitempty"`
	FDCount  int    `json:"fd_count,omitempty"`
	Duration string `json:"duration,omitempty"`
	DstAddr  string `json:"dst_addr,omitempty"`
	Args     string `json:"args,omitempty"`
}

var sensitiveFiles = []string{"/etc/passwd", "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/crontab"}
var sensitiveSubstrings = []string{"/.ssh/", "/id_rsa", "/id_ed25519", "/.gnupg/", "/proc/1/mem", "/proc/1/maps", "/run/secrets", "/var/run/secrets"}
var sensitivePrefixes = []string{"/root/", "/etc/sudoers.d/", "/etc/cron.d/"}

func IsSensitive(path string) bool {
	for _, f := range sensitiveFiles {
		if path == f {
			return true
		}
	}
	for _, sub := range sensitiveSubstrings {
		if strings.Contains(path, sub) {
			return true
		}
	}
	for _, prefix := range sensitivePrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func FmtDuration(ns uint64) string {
	switch {
	case ns < 1_000:
		return fmt.Sprintf("%dns", ns)
	case ns < 1_000_000:
		return fmt.Sprintf("%.2fµs", float64(ns)/1e3)
	case ns < 1_000_000_000:
		return fmt.Sprintf("%.2fms", float64(ns)/1e6)
	case ns < 60_000_000_000:
		return fmt.Sprintf("%.3fs", float64(ns)/1e9)
	default:
		secs := ns / 1_000_000_000
		return fmt.Sprintf("%dh %dm %ds", secs/3600, (secs%3600)/60, secs%60)
	}
}