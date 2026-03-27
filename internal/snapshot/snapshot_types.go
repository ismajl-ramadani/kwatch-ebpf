package snapshot

import (
	"time"
)

type ProcessSource string

const (
	SourceSnapshot ProcessSource = "snapshot"
)

type ProcessInfo struct {
	PID       uint32        `json:"pid"`
	PPID      uint32        `json:"ppid"`
	Command   string        `json:"command"`
	Status    string        `json:"status"`
	Source    ProcessSource `json:"source"`
	StartTime time.Time     `json:"start_time"`
}

type SnapshotJSON struct {
	Type      string                  `json:"type"`
	Processes map[uint32]*ProcessInfo `json:"processes"`
}
