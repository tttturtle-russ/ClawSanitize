package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tttturtle-russ/ClawSanitizer/internal/types"
)

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name,omitempty"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	FullDescription  sarifMessage        `json:"fullDescription,omitempty"`
	Help             sarifMessage        `json:"help,omitempty"`
	Properties       sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	Tags     []string `json:"tags,omitempty"`
	Severity string   `json:"security-severity,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

func PrintSARIF(result *types.ScanResult, w io.Writer) error {
	ruleIndex := map[string]int{}
	var rules []sarifRule
	var results []sarifResult

	for _, f := range result.Findings {
		if _, seen := ruleIndex[f.ID]; !seen {
			ruleIndex[f.ID] = len(rules)
			rules = append(rules, buildSARIFRule(f))
		}
		results = append(results, buildSARIFResult(f))
	}

	version := result.Version
	if version == "" {
		version = "dev"
	}

	report := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "clawsan",
					Version:        version,
					InformationURI: "https://github.com/tttturtle-russ/ClawSanitizer",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func WriteSARIF(result *types.ScanResult, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create SARIF file: %w", err)
	}
	defer f.Close()
	return PrintSARIF(result, f)
}

func buildSARIFRule(f types.Finding) sarifRule {
	tags := []string{f.Category}
	if f.OWASP != "" {
		tags = append(tags, f.OWASP)
	}
	r := sarifRule{
		ID:               f.ID,
		Name:             slugify(f.Title),
		ShortDescription: sarifMessage{Text: f.Title},
		FullDescription:  sarifMessage{Text: f.Description},
		Help:             sarifMessage{Text: f.Remediation},
		Properties: sarifRuleProperties{
			Tags:     tags,
			Severity: severityToNumeric(f.Severity),
		},
	}
	return r
}

func buildSARIFResult(f types.Finding) sarifResult {
	r := sarifResult{
		RuleID:  f.ID,
		Level:   severityToSARIFLevel(f.Severity),
		Message: sarifMessage{Text: f.Description},
	}
	if f.FilePath != "" {
		loc := sarifLocation{
			PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{
					URI:       filepath.ToSlash(f.FilePath),
					URIBaseID: "%SRCROOT%",
				},
			},
		}
		if f.LineNumber > 0 {
			loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.LineNumber}
		}
		r.Locations = []sarifLocation{loc}
	}
	return r
}

func severityToSARIFLevel(sev string) string {
	switch sev {
	case types.SeverityCritical, types.SeverityHigh:
		return "error"
	case types.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func severityToNumeric(sev string) string {
	switch sev {
	case types.SeverityCritical:
		return "9.8"
	case types.SeverityHigh:
		return "7.5"
	case types.SeverityMedium:
		return "5.0"
	default:
		return "2.0"
	}
}

func slugify(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, s)
}
