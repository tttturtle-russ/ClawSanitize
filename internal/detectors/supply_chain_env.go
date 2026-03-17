package detectors

import (
	"fmt"

	"github.com/tttturtle-russ/ClawSanitizer/internal/types"
)

var sensitiveEnvKeys = map[string]bool{
	"HOST":          true,
	"PORT":          true,
	"OPENCLAW_HOME": true,
	"GATEWAY_URL":   true,
}

type SupplyChainEnvDetector struct{}

func NewSupplyChainEnvDetector() *SupplyChainEnvDetector {
	return &SupplyChainEnvDetector{}
}

func (d *SupplyChainEnvDetector) Detect(cfg *types.OpenClawConfig) []types.Finding {
	if cfg == nil {
		return nil
	}
	return d.checkSC017EnvOverrides(cfg)
}

func (d *SupplyChainEnvDetector) checkSC017EnvOverrides(cfg *types.OpenClawConfig) []types.Finding {
	var findings []types.Finding
	for skillName, entry := range cfg.Skills.Entries {
		for key, val := range entry.Env {
			if sensitiveEnvKeys[key] {
				findings = append(findings, types.Finding{
					ID:       "SC-017",
					Severity: types.SeverityHigh,
					Category: types.CategorySupplyChain,
					Title: fmt.Sprintf(
						"Skill %q overrides critical env var %q",
						skillName, key,
					),
					Description: fmt.Sprintf(
						"skills.entries[%q].env[%q]=%q overrides a critical platform environment variable. "+
							"A malicious skill can redirect the agent's gateway, home directory, or listener address to an attacker-controlled endpoint.",
						skillName, key, val,
					),
					Remediation: fmt.Sprintf(
						"Remove %q from the env map for skill %q. "+
							"Critical platform variables must not be overridable by individual skills.",
						key, skillName,
					),
					OWASP: types.OWASPLLM03,
					CWE:   "CWE-15: External Control of System or Configuration Setting",
				})
			}
		}
	}
	return findings
}
