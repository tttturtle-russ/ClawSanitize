package output

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/tttturtle-russ/clawsan/internal/types"
)

var (
	criticalColor = color.New(color.FgRed, color.Bold)
	highColor     = color.New(color.FgYellow, color.Bold)
	mediumColor   = color.New(color.FgBlue)
	lowColor      = color.New(color.FgCyan)
	infoColor     = color.New(color.FgGreen)
	boldColor     = color.New(color.Bold)
)

// PrintFindings prints all findings with color-coded severity to stdout
func PrintFindings(findings []types.Finding) {
	if len(findings) == 0 {
		infoColor.Println("✅ No vulnerabilities found.")
		return
	}
	for _, f := range findings {
		printFinding(f)
	}
}

func printFinding(f types.Finding) {
	// Print severity badge + title
	severityLabel := severityColor(f.Severity)
	severityLabel.Printf("[%s] ", f.Severity)
	boldColor.Printf("%s\n", f.Title)
	// Print ID and category
	fmt.Printf("  ID: %s | Category: %s\n", f.ID, f.Category)
	// Print description
	fmt.Printf("  %s\n", f.Description)
	// Print remediation
	fmt.Printf("  💡 Fix: %s\n", f.Remediation)
	// Print file path if present
	if f.FilePath != "" {
		fmt.Printf("  📁 File: %s\n", f.FilePath)
	}
	fmt.Println()
}

func severityColor(severity string) *color.Color {
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
		return infoColor
	}
}

// PrintSummary prints the final scan summary with score
func PrintSummary(result types.ScanResult) {
	fmt.Println("─────────────────────────────────────")
	boldColor.Printf("Security Score: %d/100\n", result.Score)
	fmt.Printf("Total Checks: %d | Findings: %d\n", result.TotalChecks, len(result.Findings))
	if result.Summary != "" {
		fmt.Printf("Summary: %s\n", result.Summary)
	}
}
