package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/models"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/tracer"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the eBPF agent and stream JSON logs to stdout",
	Run: func(cmd *cobra.Command, args []string) {
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
				data, _ := json.Marshal(ev)
				fmt.Println(string(data))
			}
		}()

		if err := tracer.Start(eventChan, stopChan); err != nil {
			log.Fatalf("Tracer failed: %v", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}