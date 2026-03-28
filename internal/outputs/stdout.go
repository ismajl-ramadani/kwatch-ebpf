package outputs

import (
	"encoding/json"
	"fmt"

	"github.com/ismajl-ramadani/kwatch-ebpf/internal/models"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/snapshot"
)

type StdoutOutput struct{}

func NewStdoutOutput() *StdoutOutput {
	return &StdoutOutput{}
}

func (s *StdoutOutput) Init() error {
	return nil
}

func (s *StdoutOutput) SendSnapshot(snap *snapshot.SnapshotJSON) error {
	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func (s *StdoutOutput) SendEvent(ev models.EventJSON) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func (s *StdoutOutput) Close() error {
	return nil
}
