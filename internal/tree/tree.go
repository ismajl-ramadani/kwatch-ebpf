package tree

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ismajl-ramadani/kwatch-ebpf/internal/models"
)

type TreeManager struct {
	processes map[uint32]*ProcessNode
	mu        sync.RWMutex
	procPath  string
}

func NewTreeManager(optProcPath string) *TreeManager {
	if optProcPath == "" {
		optProcPath = "/proc"
	}
	return &TreeManager{
		processes: make(map[uint32]*ProcessNode),
		procPath:  optProcPath,
	}
}

func (t *TreeManager) BuildSnapshot() (*TreeSnapshotJSON, error) {
	btime := t.getSystemBootTime()

	entries, err := os.ReadDir(t.procPath)
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue // not a PID directory
		}

		pidPath := filepath.Join(t.procPath, entry.Name())

		ppid, name := t.parseStatusFile(filepath.Join(pidPath, "status"))

		cmdline := t.parseCmdlineFile(filepath.Join(pidPath, "cmdline"))
		if cmdline == "" {
			cmdline = name // fallback
		}
		startTime := t.parseStartTime(filepath.Join(pidPath, "stat"), btime)

		node := &ProcessNode{
			PID:                uint32(pid),
			PPID:               ppid,
			Command:            cmdline,
			Status:             "alive",
			Source:             SourceSnapshot,
			StartTime:          startTime,
			NetworkConnections: make([]string, 0),
			FileAccesses:       make([]string, 0),
		}

		t.processes[uint32(pid)] = node
	}

	snapNodes := make(map[uint32]*ProcessNode)
	for k, v := range t.processes {
		snapNodes[k] = v
	}

	return &TreeSnapshotJSON{
		Type:  "snapshot",
		Nodes: snapNodes,
	}, nil
}

func (t *TreeManager) ProcessEvent(ev models.EventJSON) EventDiffJSON {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch ev.Type {
	case "exec":
		node := &ProcessNode{
			PID:                ev.PID,
			PPID:               ev.PPID,
			Command:            ev.Command,
			Path:               ev.Path,
			Status:             "alive",
			Source:             SourceEvent,
			StartTime:          time.Now(), // We use current time for runtime exec
			NetworkConnections: make([]string, 0),
			FileAccesses:       make([]string, 0),
		}

		if existing, ok := t.processes[ev.PID]; ok && existing.Source == SourcePhantom {
			node.NetworkConnections = existing.NetworkConnections
			node.FileAccesses = existing.FileAccesses
		}

		t.processes[ev.PID] = node

		return EventDiffJSON{
			Type: "node_added",
			Node: node,
		}

	case "exit":
		if node, ok := t.processes[ev.PID]; ok {
			node.Status = "dead"
			node.EndTime = time.Now()
			return EventDiffJSON{
				Type: "node_exited",
				Node: node,
			}
		}
		phantom := t.createPhantomNode(ev.PID)
		phantom.Status = "dead"
		phantom.EndTime = time.Now()
		return EventDiffJSON{
			Type: "node_exited",
			Node: phantom,
		}

	case "connect", "open":
		node, ok := t.processes[ev.PID]
		if !ok {
			node = t.createPhantomNode(ev.PID)
		}

		if ev.Type == "connect" && ev.DstAddr != "" {
			node.NetworkConnections = append(node.NetworkConnections, ev.DstAddr)
		} else if ev.Type == "open" && ev.Path != "" {
			node.FileAccesses = append(node.FileAccesses, ev.Path)
		}

		return EventDiffJSON{
			Type: "node_updated",
			Node: node,
		}
	}

	return EventDiffJSON{}
}

// Helpers

func (t *TreeManager) createPhantomNode(pid uint32) *ProcessNode {
	n := &ProcessNode{
		PID:                pid,
		Status:             "alive",
		Source:             SourcePhantom,
		StartTime:          time.Now(),
		NetworkConnections: make([]string, 0),
		FileAccesses:       make([]string, 0),
	}
	t.processes[pid] = n
	return n
}

func (t *TreeManager) getSystemBootTime() time.Time {
	data, err := os.ReadFile(filepath.Join(t.procPath, "stat"))
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

func (t *TreeManager) parseStatusFile(path string) (uint32, string) {
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

func (t *TreeManager) parseCmdlineFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return ""
	}
	// cmdline args are null separated
	data = bytes.ReplaceAll(data, []byte{0}, []byte{' '})
	return strings.TrimSpace(string(data))
}

func (t *TreeManager) parseStartTime(path string, btime time.Time) time.Time {
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
