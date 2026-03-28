package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/config"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/models"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/outputs"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/snapshot"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/tracer"
)

var configPath string

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the eBPF agent and stream events",
	Run: func(cmd *cobra.Command, args []string) {
		mux := outputs.NewMultiplexer()
		mux.Add(outputs.NewStdoutOutput())

		if configPath != "" {
			cfg, err := config.Load(configPath)
			if err != nil {
				log.Fatalf("Failed to load config: %v", err)
			}

			if cfg.Outputs.Prometheus != nil && cfg.Outputs.Prometheus.Enabled {
				mux.Add(outputs.NewPrometheusOutput(cfg.Outputs.Prometheus))
			}
			if cfg.Outputs.Websocket != nil && cfg.Outputs.Websocket.Enabled {
				mux.Add(outputs.NewWebsocketOutput(cfg.Outputs.Websocket))
			}
			if cfg.Outputs.MQTT != nil && cfg.Outputs.MQTT.Enabled {
				mux.Add(outputs.NewMqttOutput(cfg.Outputs.MQTT))
			}
		}

		if err := mux.InitAll(); err != nil {
			log.Fatalf("Failed to initialize outputs: %v", err)
		}
		defer mux.CloseAll()

		engine := snapshot.NewSnapshotEngine("/proc")
		if snap, err := engine.Build(); err != nil {
			log.Printf("Warning: failed to build process snapshot: %v", err)
		} else {
			mux.SendSnapshot(snap)
		}

		eventChan := make(chan models.EventJSON, 1000)
		stopChan := make(chan struct{})

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigChan
			log.Println("\nShutting down kwatch...")
			close(stopChan)
		}()

		go func() {
			for ev := range eventChan {
				mux.SendEvent(ev)
			}
		}()

		if err := tracer.Start(eventChan, stopChan); err != nil {
			log.Fatalf("Tracer failed: %v", err)
		}
	},
}

func init() {
	startCmd.Flags().StringVar(&configPath, "config", "", "Path to config YAML file")
	rootCmd.AddCommand(startCmd)
}