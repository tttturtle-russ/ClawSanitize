package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/tttturtle-russ/clawsan/internal/types"
)

var (
	criticalColor = color.New(color.FgRed, color.Bold)
	highColor     = color.New(color.FgYellow, color.Bold)
	mediumColor   = color.New(color.FgBlue)
	lowColor      = color.New(color.FgCyan)
	successColor  = color.New(color.FgGreen, color.Bold)
	boldColor     = color.New(color.Bold)
	dimColor      = color.New(color.Faint)
)

type PrintOptions struct {
	Quiet       bool
	NoColor     bool
	MinSeverity string
	Writer      io.Writer
}

func DefaultPrintOptions() PrintOptions {
	return PrintOptions{Writer: os.Stdout}
}

func PrintBanner(result *types.ScanResult, opts PrintOptions) {
	if opts.Quiet {
		return
	}
	w := opts.Writer
	if opts.NoColor {
		color.NoColor = true
	}

	banner := `
 ██████╗██╗      █████╗ ██╗    ██╗███████╗ █████╗ ███╗   ██╗
██╔════╝██║     ██╔══██╗██║    ██║██╔════╝██╔══██╗████╗  ██║
██║     ██║     ███████║██║ █╗ ██║███████╗███████║██╔██╗ ██║
██║     ██║     ██╔══██║██║███╗██║╚════██║██╔══██║██║╚██╗██║
╚██████╗███████╗██║  ██║╚███╔███╔╝███████║██║  ██║██║ ╚████║
 ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝`
	boldColor.Fprintln(w, banner)
	fmt.Fprintln(w)
	boldColor.Fprintf(w, "  OpenClaw Security Scanner")
	if result.Version != "" {
		dimColor.Fprintf(w, " %s", result.Version)
	}
	fmt.Fprintln(w)
	dimColor.Fprintf(w, "  Scanning: %s\n", result.ScannedPath)
	dimColor.Fprintf(w, "  Started:  %s\n", result.ScannedAt.Format(time.RFC3339))
	fmt.Fprintln(w, strings.Repeat("─", 70))
	fmt.Fprintln(w)
}

func PrintFindings(result *types.ScanResult, opts PrintOptions) {
	w := opts.Writer
	if opts.NoColor {
		color.NoColor = true
	}

	minSev := severityRank(opts.MinSeverity)
	shown := 0

	for _, f := range result.Findings {
		if severityRank(f.Severity) < minSev {
			continue
		}
		if !opts.Quiet {
			printFinding(w, f)
		}
		shown++
	}

	if shown == 0 && !opts.Quiet {
		successColor.Fprintln(w, "✅  No findings above the minimum severity threshold.")
		fmt.Fprintln(w)
	}
}

func printFinding(w io.Writer, f types.Finding) {
	sev := severityColorFor(f.Severity)
	sev.Fprintf(w, "  ┌ [%s]", f.Severity)
	fmt.Fprintf(w, " %s\n", f.Title)
	dimColor.Fprintf(w, "  │ ID: %s", f.ID)
	if f.OWASP != "" {
		dimColor.Fprintf(w, "  │  OWASP: %s", f.OWASP)
	}
	if f.CWE != "" {
		dimColor.Fprintf(w, "  │  CWE: %s", f.CWE)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  │ %s\n", f.Description)
	fmt.Fprintf(w, "  └ 💡 %s\n", f.Remediation)
	if f.FilePath != "" {
		dimColor.Fprintf(w, "     📁 %s\n", f.FilePath)
	}
	fmt.Fprintln(w)
}

func PrintSummary(result *types.ScanResult, opts PrintOptions) {
	w := opts.Writer
	if opts.NoColor {
		color.NoColor = true
	}
	fmt.Fprintln(w, strings.Repeat("─", 70))
	fmt.Fprintln(w)

	gradeColor := gradeColorFor(result.Grade)
	boldColor.Fprintf(w, "  Security Score: ")
	gradeColor.Fprintf(w, "%d/100  Grade: %s\n", result.Score, result.Grade)
	fmt.Fprintln(w)

	fmt.Fprintf(w, "  Checks run:  %d\n", result.TotalChecks)
	fmt.Fprintf(w, "  Duration:    %dms\n", result.DurationMs)
	fmt.Fprintln(w)

	boldColor.Fprintln(w, "  Findings by severity:")
	printSeverityRow(w, "CRITICAL", result.Critical, criticalColor)
	printSeverityRow(w, "HIGH    ", result.High, highColor)
	printSeverityRow(w, "MEDIUM  ", result.Medium, mediumColor)
	printSeverityRow(w, "LOW     ", result.Low, lowColor)
	fmt.Fprintln(w)

	if len(result.Warnings) > 0 {
		for _, warn := range result.Warnings {
			dimColor.Fprintf(w, "  ⚠  %s\n", warn)
		}
		fmt.Fprintln(w)
	}
}

func printSeverityRow(w io.Writer, label string, count int, c *color.Color) {
	bar := strings.Repeat("█", count)
	if count == 0 {
		bar = "·"
	}
	c.Fprintf(w, "  %s  %2d  %s\n", label, count, bar)
}

func gradeColorFor(grade string) *color.Color {
	switch grade {
	case "A":
		return color.New(color.FgGreen, color.Bold)
	case "B":
		return color.New(color.FgCyan, color.Bold)
	case "C":
		return color.New(color.FgYellow, color.Bold)
	case "D":
		return color.New(color.FgHiYellow, color.Bold)
	default:
		return color.New(color.FgRed, color.Bold)
	}
}

func severityColorFor(severity string) *color.Color {
	switch severity {
	case types.SeverityCritical:
		return criticalColor
	case types.SeverityHigh:
		return highColor
	case types.SeverityMedium:
		return mediumColor
	case types.SeverityLow:
		return lowColor
	default:
		return successColor
	}
}

func severityRank(sev string) int {
	switch strings.ToUpper(sev) {
	case types.SeverityCritical:
		return 4
	case types.SeverityHigh:
		return 3
	case types.SeverityMedium:
		return 2
	case types.SeverityLow:
		return 1
	default:
		return 0
	}
}

func HasFindingsAbove(result *types.ScanResult, minSeverity string) bool {
	rank := severityRank(minSeverity)
	for _, f := range result.Findings {
		if severityRank(f.Severity) >= rank {
			return true
		}
	}
	return false
}
