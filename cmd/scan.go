package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var scanPath string
var scanJSON bool

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan an OpenClaw installation for security vulnerabilities",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Scanning...")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVar(&scanPath, "path", "~/.openclaw/", "path to OpenClaw installation")
	scanCmd.Flags().BoolVar(&scanJSON, "json", false, "output results as JSON")
}
