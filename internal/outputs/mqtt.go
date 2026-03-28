package outputs

import (
	"encoding/json"
	"log"

	"github.com/eclipse/paho.mqtt.golang"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/config"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/models"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/snapshot"
)

type MqttOutput struct {
	broker string
	topic  string
	client mqtt.Client
}

func NewMqttOutput(cfg *config.MQTTConfig) *MqttOutput {
	return &MqttOutput{
		broker: cfg.Broker,
		topic:  cfg.Topic,
	}
}

func (m *MqttOutput) Init() error {
	opts := mqtt.NewClientOptions().
		AddBroker(m.broker).
		SetClientID("kwatch-ebpf")

	m.client = mqtt.NewClient(opts)

	token := m.client.Connect()
	token.Wait()
	if err := token.Error(); err != nil {
		return err
	}

	log.Printf("MQTT connected to %s, publishing to topic %s", m.broker, m.topic)
	return nil
}

func (m *MqttOutput) SendSnapshot(snap *snapshot.SnapshotJSON) error {
	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	token := m.client.Publish(m.topic, 0, false, data)
	token.Wait()
	return token.Error()
}

func (m *MqttOutput) SendEvent(ev models.EventJSON) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	token := m.client.Publish(m.topic, 0, false, data)
	token.Wait()
	return token.Error()
}

func (m *MqttOutput) Close() error {
	if m.client != nil && m.client.IsConnected() {
		m.client.Disconnect(1000)
	}
	return nil
}
