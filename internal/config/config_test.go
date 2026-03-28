package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	yamlContent := `
outputs:
  prometheus:
    enabled: true
    port: 9090
  mqtt:
    enabled: true
    broker: "tcp://localhost:1883"
    topic: "kwatch/events"
  websocket:
    enabled: false
    port: 3000
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if cfg.Outputs.Prometheus == nil || !cfg.Outputs.Prometheus.Enabled {
		t.Error("expected prometheus to be enabled")
	}
	if cfg.Outputs.Prometheus.Port != 9090 {
		t.Errorf("expected prometheus port 9090, got %d", cfg.Outputs.Prometheus.Port)
	}

	if cfg.Outputs.MQTT == nil || !cfg.Outputs.MQTT.Enabled {
		t.Error("expected mqtt to be enabled")
	}
	if cfg.Outputs.MQTT.Broker != "tcp://localhost:1883" {
		t.Errorf("expected mqtt broker tcp://localhost:1883, got %s", cfg.Outputs.MQTT.Broker)
	}

	if cfg.Outputs.Websocket == nil || cfg.Outputs.Websocket.Enabled {
		t.Error("expected websocket to be disabled")
	}
	if cfg.Outputs.Websocket.Port != 3000 {
		t.Errorf("expected websocket port 3000, got %d", cfg.Outputs.Websocket.Port)
	}
}

func TestLoadDefaults(t *testing.T) {
	yamlContent := `
outputs:
  prometheus:
    enabled: true
  websocket:
    enabled: true
  mqtt:
    enabled: true
    broker: "tcp://localhost:1883"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if cfg.Outputs.Prometheus.Port != 2112 {
		t.Errorf("expected default prometheus port 2112, got %d", cfg.Outputs.Prometheus.Port)
	}
	if cfg.Outputs.Websocket.Port != 8080 {
		t.Errorf("expected default websocket port 8080, got %d", cfg.Outputs.Websocket.Port)
	}
	if cfg.Outputs.MQTT.Topic != "kwatch/events" {
		t.Errorf("expected default mqtt topic kwatch/events, got %s", cfg.Outputs.MQTT.Topic)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for missing config file")
	}
}

func TestLoadEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() failed on empty config: %v", err)
	}

	if cfg.Outputs.Prometheus != nil {
		t.Error("expected prometheus to be nil when not configured")
	}
	if cfg.Outputs.MQTT != nil {
		t.Error("expected mqtt to be nil when not configured")
	}
	if cfg.Outputs.Websocket != nil {
		t.Error("expected websocket to be nil when not configured")
	}
}
