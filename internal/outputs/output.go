package outputs

import (
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/models"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/snapshot"
)

type Output interface {
	Init() error
	SendSnapshot(snap *snapshot.SnapshotJSON) error
	SendEvent(ev models.EventJSON) error
	Close() error
}
