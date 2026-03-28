package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Outputs OutputsConfig `yaml:"outputs"`
}

type OutputsConfig struct {
	Prometheus *PrometheusConfig `yaml:"prometheus"`
	MQTT       *MQTTConfig       `yaml:"mqtt"`
	Websocket  *WebsocketConfig  `yaml:"websocket"`
}

type PrometheusConfig struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

type MQTTConfig struct {
	Enabled bool   `yaml:"enabled"`
	Broker  string `yaml:"broker"`
	Topic   string `yaml:"topic"`
}

type WebsocketConfig struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	setDefaults(cfg)
	return cfg, nil
}

func setDefaults(cfg *Config) {
	if cfg.Outputs.Prometheus != nil && cfg.Outputs.Prometheus.Port == 0 {
		cfg.Outputs.Prometheus.Port = 2112
	}
	if cfg.Outputs.Websocket != nil && cfg.Outputs.Websocket.Port == 0 {
		cfg.Outputs.Websocket.Port = 8080
	}
	if cfg.Outputs.MQTT != nil && cfg.Outputs.MQTT.Topic == "" {
		cfg.Outputs.MQTT.Topic = "kwatch/events"
	}
}
