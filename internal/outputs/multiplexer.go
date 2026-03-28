package outputs

import (
	"log"

	"github.com/ismajl-ramadani/kwatch-ebpf/internal/models"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/snapshot"
)

type Multiplexer struct {
	outputs []Output
}

func NewMultiplexer() *Multiplexer {
	return &Multiplexer{}
}

func (m *Multiplexer) Add(o Output) {
	m.outputs = append(m.outputs, o)
}

func (m *Multiplexer) InitAll() error {
	for _, o := range m.outputs {
		if err := o.Init(); err != nil {
			return err
		}
	}
	return nil
}

func (m *Multiplexer) SendSnapshot(snap *snapshot.SnapshotJSON) {
	for _, o := range m.outputs {
		if err := o.SendSnapshot(snap); err != nil {
			log.Printf("output error (snapshot): %v", err)
		}
	}
}

func (m *Multiplexer) SendEvent(ev models.EventJSON) {
	for _, o := range m.outputs {
		if err := o.SendEvent(ev); err != nil {
			log.Printf("output error (event): %v", err)
		}
	}
}

func (m *Multiplexer) CloseAll() {
	for _, o := range m.outputs {
		if err := o.Close(); err != nil {
			log.Printf("output error (close): %v", err)
		}
	}
}
