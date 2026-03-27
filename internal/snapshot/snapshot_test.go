package snapshot

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
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

		if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte(cmdline+"\x00"), 0644); err != nil {
			t.Fatalf("failed to write mock cmdline file: %v", err)
		}

		if stat == "" {
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

func TestBuild(t *testing.T) {
	mockProcDir := setupMockProc(t)
	engine := NewSnapshotEngine(mockProcDir)

	snapshot, err := engine.Build()
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}

	if snapshot.Type != "snapshot" {
		t.Errorf("expected snapshot type to be 'snapshot', got %s", snapshot.Type)
	}

	if len(snapshot.Processes) != 3 {
		t.Errorf("expected 3 processes from mock procfs, got %d", len(snapshot.Processes))
	}

	node101, exists := snapshot.Processes[101]
	if !exists {
		t.Fatalf("expected PID 101 to exist")
	}

	if node101.PPID != 100 {
		t.Errorf("expected PPID of 101 to be 100, got %d", node101.PPID)
	}

	if node101.Command != "bash" {
		t.Errorf("expected command 'bash', got %s", node101.Command)
	}

	if node101.Status != "alive" {
		t.Errorf("expected status 'alive', got %s", node101.Status)
	}

	if node101.Source != SourceSnapshot {
		t.Errorf("expected source to be snapshot, got %s", node101.Source)
	}

	if node101.StartTime.IsZero() {
		t.Errorf("expected StartTime to be populated")
	}
}
