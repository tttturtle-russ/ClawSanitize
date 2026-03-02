package scoring

import "github.com/yourusername/clawsanitizer/internal/types"

// CalculateScore computes a severity-weighted vulnerability score from 0-100.
// Starts with base score of 100 and deducts points for each finding based on severity:
// - CRITICAL: 25 points each
// - HIGH: 10 points each
// - MEDIUM: 5 points each
// - LOW: 1 point each
// - INFO: 0 points each
// Result is clamped to minimum 0 (never negative).
func CalculateScore(findings []types.Finding) int {
	score := 100

	for _, finding := range findings {
		switch finding.Severity {
		case types.SeverityCritical:
			score -= 25
		case types.SeverityHigh:
			score -= 10
		case types.SeverityMedium:
			score -= 5
		case types.SeverityLow:
			score -= 1
		case types.SeverityInfo:
			// INFO severity: no deduction
		}
	}

	// Clamp to minimum 0
	if score < 0 {
		score = 0
	}

	return score
}
