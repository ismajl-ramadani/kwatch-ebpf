package tree

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ismajl-ramadani/kwatch-ebpf/internal/models"
)

func setupMockProc(t *testing.T) string {
	procDir := t.TempDir()

	createProcProcess := func(pid, ppid int, cmdline, stat string) {
		pidDir := filepath.Join(procDir, fmt.Sprintf("%d", pid))
		if err := os.MkdirAll(pidDir, 0755); err != nil {
			t.Fatalf("failed to create mock proc dir: %v", err)
		}

		statusData := fmt.Sprintf("Name:\t%s\nState:\tS (sleeping)\nPPid:\t%d\n", cmdline, ppid)
		if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte(statusData), 0644); err != nil {
			t.Fatalf("failed to write mock status file: %v", err)
		}

		// cmdline uses null bytes to separate args in real /proc
		if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte(cmdline+"\x00"), 0644); err != nil {
			t.Fatalf("failed to write mock cmdline file: %v", err)
		}

		// stat file is used to get the start time (field 22 usually)
		// Format: pid comm state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime cutime cstime priority nice num_threads itrealvalue starttime ...
		if stat == "" {
			// Mocking field 22 as 1000 (jiffies since boot)
			stat = fmt.Sprintf("%d (%s) S %d 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1000", pid, cmdline, ppid)
		}
		if err := os.WriteFile(filepath.Join(pidDir, "stat"), []byte(stat), 0644); err != nil {
			t.Fatalf("failed to write mock stat file: %v", err)
		}
	}

	createProcProcess(1, 0, "systemd", "")
	createProcProcess(100, 1, "sshd", "")
	createProcProcess(101, 100, "bash", "")

	return procDir
}

func TestBuildSnapshot(t *testing.T) {
	mockProcDir := setupMockProc(t)
	tm := NewTreeManager(mockProcDir)

	snapshot, err := tm.BuildSnapshot()
	if err != nil {
		t.Fatalf("BuildSnapshot failed: %v", err)
	}

	if snapshot.Type != "snapshot" {
		t.Errorf("Expected snapshot type to be 'snapshot', got %s", snapshot.Type)
	}

	if len(snapshot.Nodes) != 3 {
		t.Errorf("Expected 3 processes from mock procfs, got %d", len(snapshot.Nodes))
	}

	node101, exists := snapshot.Nodes[101]
	if !exists {
		t.Fatalf("Expected PID 101 to exist")
	}

	if node101.PPID != 100 {
		t.Errorf("Expected PPID of 101 to be 100, got %d", node101.PPID)
	}

	if node101.Command != "bash" {
		t.Errorf("Expected command 'bash', got %s", node101.Command)
	}

	if node101.Status != "alive" {
		t.Errorf("Expected status 'alive', got %s", node101.Status)
	}

	if node101.Source != SourceSnapshot {
		t.Errorf("Expected source to be snapshot, got %s", node101.Source)
	}

	if node101.StartTime.IsZero() {
		t.Errorf("Expected StartTime to be populated")
	}
}

func TestProcessEvent_Exec_And_Exit(t *testing.T) {
	tm := NewTreeManager("")

	execEvent := models.EventJSON{
		Type:    "exec",
		PID:     1000,
		PPID:    500,
		Command: "nc",
		Path:    "/usr/bin/nc",
	}

	diffExec := tm.ProcessEvent(execEvent)

	if diffExec.Type != "node_added" {
		t.Errorf("Expected diff type 'node_added', got %s", diffExec.Type)
	}

	if diffExec.Node.PID != 1000 || diffExec.Node.Command != "nc" {
		t.Errorf("Received incorrect node in diff")
	}

	if diffExec.Node.Source != SourceEvent {
		t.Errorf("Expected source 'event', got %s", diffExec.Node.Source)
	}

	if diffExec.Node.Status != "alive" {
		t.Errorf("Expected status to be 'alive'")
	}

	exitEvent := models.EventJSON{
		Type: "exit",
		PID:  1000,
	}

	diffExit := tm.ProcessEvent(exitEvent)

	if diffExit.Type != "node_exited" {
		t.Errorf("Expected diff type 'node_exited', got %s", diffExit.Type)
	}

	if diffExit.Node.Status != "dead" {
		t.Errorf("Expected status 'dead', got %s", diffExit.Node.Status)
	}

	// Verify it still exists in memory but is marked dead
	tm.mu.RLock()
	node, exists := tm.processes[1000]
	tm.mu.RUnlock()

	if !exists {
		t.Errorf("Expected node to remain in map for historical context")
	} else if node.Status != "dead" {
		t.Errorf("Expected map node to have status dead")
	}
	if node.EndTime.IsZero() {
		t.Errorf("Expected node.EndTime to be populated upon exit")
	}
}

func TestProcessEvent_Correlation(t *testing.T) {
	tm := NewTreeManager("")

	tm.ProcessEvent(models.EventJSON{
		Type:    "exec",
		PID:     2000,
		Command: "curl",
	})

	connectEvent := models.EventJSON{
		Type:    "connect",
		PID:     2000,
		DstAddr: "8.8.8.8:53",
	}

	diffConnect := tm.ProcessEvent(connectEvent)

	if diffConnect.Type != "node_updated" {
		t.Errorf("Expected diff type 'node_updated', got %s", diffConnect.Type)
	}

	if len(diffConnect.Node.NetworkConnections) != 1 || diffConnect.Node.NetworkConnections[0] != "8.8.8.8:53" {
		t.Errorf("Expected network connection to be added")
	}

	openEvent := models.EventJSON{
		Type: "open",
		PID:  2000,
		Path: "/etc/passwd",
	}

	diffOpen := tm.ProcessEvent(openEvent)

	if diffOpen.Type != "node_updated" {
		t.Errorf("Expected 'node_updated', got %s", diffOpen.Type)
	}

	if len(diffOpen.Node.FileAccesses) != 1 || diffOpen.Node.FileAccesses[0] != "/etc/passwd" {
		t.Errorf("Expected file access to be added")
	}
}

func TestProcessEvent_PhantomNode(t *testing.T) {
	tm := NewTreeManager("")

	connectEvent := models.EventJSON{
		Type:    "connect",
		PID:     3000,
		DstAddr: "1.1.1.1:443",
	}

	diff := tm.ProcessEvent(connectEvent)

	if diff.Type != "node_updated" {
		t.Errorf("Expected 'node_updated' when handling phantom creation, got %s", diff.Type)
	}

	if diff.Node.Source != SourcePhantom {
		t.Errorf("Expected source to be %v because node was unknown, got %v", SourcePhantom, diff.Node.Source)
	}

	if len(diff.Node.NetworkConnections) != 1 {
		t.Errorf("Expected network connection to be appended to phantom node")
	}

	execEvent := models.EventJSON{
		Type:    "exec",
		PID:     3000,
		Command: "wget",
	}
	
	diffExec := tm.ProcessEvent(execEvent)
	if diffExec.Type != "node_added" {
		t.Errorf("Expected 'node_added' or similar to overwrite the phantom, got %s", diffExec.Type)
	}

	if diffExec.Node.Command != "wget" {
		t.Errorf("Expected phantom node to be reconciled with actual command")
	}
}

func TestTreeManager_Concurrency(t *testing.T) {
	tm := NewTreeManager("")
	tm.ProcessEvent(models.EventJSON{Type: "exec", PID: 5000, Command: "stress"})

	var wg sync.WaitGroup
	workers := 50
	eventsPerWorker := 100

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < eventsPerWorker; j++ {
				// Simulating random events on same PID to force race detector
				if j%2 == 0 {
					tm.ProcessEvent(models.EventJSON{Type: "open", PID: 5000, Path: fmt.Sprintf("/tmp/f%d-%d", workerID, j)})
				} else {
					tm.ProcessEvent(models.EventJSON{Type: "connect", PID: 5000, DstAddr: fmt.Sprintf("10.0.%d.%d", workerID, j)})
				}

				// Also try making phantom nodes concurrently
				phantomPID := uint32(10000 + (workerID * eventsPerWorker) + j)
				tm.ProcessEvent(models.EventJSON{Type: "connect", PID: phantomPID, DstAddr: "0.0.0.0"})
				tm.ProcessEvent(models.EventJSON{Type: "exit", PID: phantomPID})
			}
		}(i)
	}

	wg.Wait()

	tm.mu.RLock()
	stressNode := tm.processes[5000]
	tm.mu.RUnlock()

	expectedItems := (workers * eventsPerWorker) / 2
	if stressNode == nil {
		t.Fatalf("Expected stressNode to exist")
	}
	
	// Ensure both slices grew to the expected boundaries without panicking
	if len(stressNode.FileAccesses) != expectedItems {
		t.Errorf("Expected %d file accesses, got %d", expectedItems, len(stressNode.FileAccesses))
	}
	if len(stressNode.NetworkConnections) != expectedItems {
		t.Errorf("Expected %d network connections, got %d", expectedItems, len(stressNode.NetworkConnections))
	}
}
