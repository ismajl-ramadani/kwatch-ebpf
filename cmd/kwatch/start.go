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
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/tree"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the eBPF agent and stream JSON logs to stdout",
	Run: func(cmd *cobra.Command, args []string) {
		treeManager := tree.NewTreeManager("/proc")
		if snapshot, err := treeManager.BuildSnapshot(); err != nil {
			log.Printf("Warning: failed to build process tree snapshot: %v", err)
		} else if raw, err := json.Marshal(snapshot); err == nil {
			fmt.Println(string(raw))
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
				diff := treeManager.ProcessEvent(ev)

				if data, err := json.Marshal(diff); err == nil {
					fmt.Println(string(data))
				}
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