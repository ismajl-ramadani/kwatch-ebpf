package main

import (
	"log"
	"os"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "kwatch",
	Short: "kwatch is an eBPF-powered kernel process monitor",
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}