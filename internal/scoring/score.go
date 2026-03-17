package scoring

import "github.com/tttturtle-russ/ClawSanitizer/internal/types"

// Severity deduction weights
const (
	weightCritical = 25
	weightHigh     = 10
	weightMedium   = 5
	weightLow      = 1
)

// CalculateScore computes a severity-weighted score from 0-100 and populates
// all ScanResult aggregate fields (Grade, severity counts, Summary).
func Calculate(findings []types.Finding) (score int, grade string, critical, high, medium, low int) {
	score = 100
	for _, f := range findings {
		switch f.Severity {
		case types.SeverityCritical:
			score -= weightCritical
			critical++
		case types.SeverityHigh:
			score -= weightHigh
			high++
		case types.SeverityMedium:
			score -= weightMedium
			medium++
		case types.SeverityLow:
			score -= weightLow
			low++
		}
	}
	if score < 0 {
		score = 0
	}
	return score, types.ScoreToGrade(score), critical, high, medium, low
}

// CalculateScore is the legacy single-return wrapper kept for backward compatibility.
func CalculateScore(findings []types.Finding) int {
	score, _, _, _, _, _ := Calculate(findings)
	return score
}
