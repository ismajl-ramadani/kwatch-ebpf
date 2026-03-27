package tree

import (
	"time"
)

type ProcessSource string

const (
	SourceSnapshot ProcessSource = "snapshot"
	SourceEvent    ProcessSource = "event"
	SourcePhantom  ProcessSource = "phantom"
)

type ProcessNode struct {
	PID                uint32        `json:"pid"`
	PPID               uint32        `json:"ppid"`
	Command            string        `json:"command"`
	Path               string        `json:"path"`
	Status             string        `json:"status"` // "alive" or "dead"
	Source             ProcessSource `json:"source"` // Distinguishes between unknown and known nodes
	StartTime          time.Time     `json:"start_time"`
	EndTime            time.Time     `json:"end_time,omitempty"`
	NetworkConnections []string      `json:"network_connections"`
	FileAccesses       []string      `json:"file_accesses"`
}

type EventDiffJSON struct {
	Type string       `json:"type"` // "node_added", "node_updated", "node_exited"
	Node *ProcessNode `json:"node"`
}

type TreeSnapshotJSON struct {
	Type  string                  `json:"type"` // "snapshot"
	Nodes map[uint32]*ProcessNode `json:"nodes"`
}
