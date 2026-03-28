package outputs

import (
	"sync"
	"testing"

	"github.com/ismajl-ramadani/kwatch-ebpf/internal/models"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/snapshot"
)

type mockOutput struct {
	mu             sync.Mutex
	initCalled     bool
	closeCalled    bool
	snapshotCount  int
	eventCount     int
}

func (m *mockOutput) Init() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.initCalled = true
	return nil
}

func (m *mockOutput) SendSnapshot(_ *snapshot.SnapshotJSON) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshotCount++
	return nil
}

func (m *mockOutput) SendEvent(_ models.EventJSON) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventCount++
	return nil
}

func (m *mockOutput) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCalled = true
	return nil
}

func TestMultiplexerBroadcast(t *testing.T) {
	mux := NewMultiplexer()
	a := &mockOutput{}
	b := &mockOutput{}
	mux.Add(a)
	mux.Add(b)

	if err := mux.InitAll(); err != nil {
		t.Fatalf("InitAll failed: %v", err)
	}

	if !a.initCalled || !b.initCalled {
		t.Error("expected Init() to be called on all outputs")
	}

	mux.SendSnapshot(&snapshot.SnapshotJSON{Type: "snapshot"})

	if a.snapshotCount != 1 || b.snapshotCount != 1 {
		t.Error("expected snapshot to be sent to all outputs")
	}

	for i := 0; i < 10; i++ {
		mux.SendEvent(models.EventJSON{Type: "exec", PID: uint32(i)})
	}

	if a.eventCount != 10 || b.eventCount != 10 {
		t.Errorf("expected 10 events each, got a=%d b=%d", a.eventCount, b.eventCount)
	}

	mux.CloseAll()

	if !a.closeCalled || !b.closeCalled {
		t.Error("expected Close() to be called on all outputs")
	}
}

func TestMultiplexerEmpty(t *testing.T) {
	mux := NewMultiplexer()

	if err := mux.InitAll(); err != nil {
		t.Fatalf("InitAll on empty mux should not fail: %v", err)
	}

	mux.SendSnapshot(&snapshot.SnapshotJSON{Type: "snapshot"})
	mux.SendEvent(models.EventJSON{Type: "exec"})
	mux.CloseAll()
}
