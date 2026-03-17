package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tttturtle-russ/ClawSanitizer/internal/output"
	"github.com/tttturtle-russ/ClawSanitizer/internal/scanner"
)

var (
	scanPath    string
	scanJSON    bool
	minSeverity string
	quiet       bool
	noColor     bool
	outputFile  string
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan an OpenClaw installation for security vulnerabilities",
	RunE: func(cmd *cobra.Command, args []string) error {
		resolvedPath := "~/.openclaw/"

		if len(args) > 0 {
			resolvedPath = args[0]
		}

		if scanPath != "" {
			resolvedPath = scanPath
		}

		if strings.HasPrefix(resolvedPath, "~/") {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: could not determine home directory: %v\n", err)
				os.Exit(2)
			}
			resolvedPath = filepath.Join(homeDir, resolvedPath[2:])
		} else if resolvedPath == "~" {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: could not determine home directory: %v\n", err)
				os.Exit(2)
			}
			resolvedPath = homeDir
		}

		if _, err := os.Stat(resolvedPath); err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Error: path not found: %s\n", resolvedPath)
			} else {
				fmt.Fprintf(os.Stderr, "Error: cannot access path: %s\n", resolvedPath)
			}
			os.Exit(2)
		}

		result, err := scanner.Scan(resolvedPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: scan failed: %v\n", err)
			os.Exit(2)
		}

		opts := output.PrintOptions{
			Quiet:       quiet,
			NoColor:     noColor,
			MinSeverity: strings.ToUpper(minSeverity),
			Writer:      os.Stdout,
		}

		if outputFile != "" {
			ext := strings.ToLower(filepath.Ext(outputFile))
			switch ext {
			case ".sarif":
				if err := output.WriteSARIF(result, outputFile); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing SARIF: %v\n", err)
					os.Exit(2)
				}
			case ".json":
				f, err := os.Create(outputFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
					os.Exit(2)
				}
				defer f.Close()
				if err := output.WriteJSON(result, f); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing JSON: %v\n", err)
					os.Exit(2)
				}
			default:
				fmt.Fprintf(os.Stderr, "Error: unsupported output format %q (use .sarif or .json)\n", ext)
				os.Exit(2)
			}
			if output.HasFindingsAbove(result, opts.MinSeverity) {
				os.Exit(1)
			}
			os.Exit(0)
		}

		if scanJSON {
			if err := output.WriteJSON(result, os.Stdout); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(2)
			}
			os.Exit(0)
		}

		output.PrintBanner(result, opts)
		output.PrintFindings(result, opts)
		output.PrintSummary(result, opts)

		if output.HasFindingsAbove(result, opts.MinSeverity) {
			os.Exit(1)
		}
		os.Exit(0)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVar(&scanPath, "path", "", "path to OpenClaw installation")
	scanCmd.Flags().BoolVar(&scanJSON, "json", false, "output results as JSON to stdout")
	scanCmd.Flags().StringVar(&minSeverity, "min-severity", "LOW", "minimum severity to report and trigger exit code 1 (LOW, MEDIUM, HIGH, CRITICAL)")
	scanCmd.Flags().BoolVar(&quiet, "quiet", false, "suppress all output except errors")
	scanCmd.Flags().BoolVar(&noColor, "no-color", false, "disable color output")
	scanCmd.Flags().StringVar(&outputFile, "output", "", "write output to file (.sarif or .json)")
}
