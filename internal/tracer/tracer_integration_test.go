//go:build integration

package tracer_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ismajl-ramadani/kwatch-ebpf/internal/models"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/tracer"
)

func TestBasicExecTracing(t *testing.T) {
	// eBPF tests must run as root 
	if os.Getuid() != 0 {
		t.Skip("Skipping test: requires root privileges")
	}

	eventChan := make(chan models.EventJSON, 100)
	stopChan := make(chan struct{})

	// Start the tracer in the background
	go func() {
		if err := tracer.Start(eventChan, stopChan); err != nil {
			t.Errorf("Failed to start tracer: %v", err)
		}
	}()

	// Give the tracer a moment to initialize
	time.Sleep(500 * time.Millisecond)

	// Execute a standard system command with a unique arg
	uniqueArg := "kwatch_test_arg"
	cmd := exec.Command("echo", uniqueArg)
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to execute command: %v", err)
	}

	// Cleanup tracer when the test ends
	defer close(stopChan)

	timeout := time.After(3 * time.Second)
	for {
		select {
		case ev := <-eventChan:
			if ev.Type == "exec" && strings.Contains(ev.Args, uniqueArg) {
				t.Logf("Success! Caught the exec event for path: %s", ev.Path)
				return
			}
		case <-timeout:
			t.Fatal("Timeout waiting for exec event. The tracer did not catch the command.")
		}
	}
}