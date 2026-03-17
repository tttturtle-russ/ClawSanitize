package scoring

import (
	"testing"

	"github.com/tttturtle-russ/ClawSanitizer/internal/types"
)

func TestCalculateScore(t *testing.T) {
	tests := []struct {
		name     string
		findings []types.Finding
		expected int
	}{
		{
			name:     "empty findings",
			findings: []types.Finding{},
			expected: 100,
		},
		{
			name: "1 CRITICAL",
			findings: []types.Finding{
				{Severity: types.SeverityCritical},
			},
			expected: 75,
		},
		{
			name: "1 HIGH",
			findings: []types.Finding{
				{Severity: types.SeverityHigh},
			},
			expected: 90,
		},
		{
			name: "1 MEDIUM",
			findings: []types.Finding{
				{Severity: types.SeverityMedium},
			},
			expected: 95,
		},
		{
			name: "1 LOW",
			findings: []types.Finding{
				{Severity: types.SeverityLow},
			},
			expected: 99,
		},
		{
			name: "4 CRITICAL",
			findings: []types.Finding{
				{Severity: types.SeverityCritical},
				{Severity: types.SeverityCritical},
				{Severity: types.SeverityCritical},
				{Severity: types.SeverityCritical},
			},
			expected: 0,
		},
		{
			name: "5 CRITICAL clamped",
			findings: []types.Finding{
				{Severity: types.SeverityCritical},
				{Severity: types.SeverityCritical},
				{Severity: types.SeverityCritical},
				{Severity: types.SeverityCritical},
				{Severity: types.SeverityCritical},
			},
			expected: 0,
		},
		{
			name: "5 MEDIUM",
			findings: []types.Finding{
				{Severity: types.SeverityMedium},
				{Severity: types.SeverityMedium},
				{Severity: types.SeverityMedium},
				{Severity: types.SeverityMedium},
				{Severity: types.SeverityMedium},
			},
			expected: 75,
		},
		{
			name: "1 CRITICAL 1 HIGH",
			findings: []types.Finding{
				{Severity: types.SeverityCritical},
				{Severity: types.SeverityHigh},
			},
			expected: 65,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateScore(tt.findings)
			if result != tt.expected {
				t.Errorf("CalculateScore() = %d, want %d", result, tt.expected)
			}
		})
	}
}
