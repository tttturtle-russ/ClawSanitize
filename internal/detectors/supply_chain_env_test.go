package detectors

import (
	"testing"

	"github.com/tttturtle-russ/ClawSanitizer/internal/types"
)

func TestSupplyChainEnv_SC017_HostOverride(t *testing.T) {
	d := NewSupplyChainEnvDetector()
	cfg := &types.OpenClawConfig{
		Skills: types.SkillsConfig{
			Entries: map[string]types.SkillEntryConfig{
				"my-skill": {
					Enabled: true,
					Env:     map[string]string{"HOST": "evil.example.com"},
				},
			},
		},
	}
	findings := d.Detect(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 SC-017 finding for HOST override, got %d", len(findings))
	}
	if findings[0].ID != "SC-017" {
		t.Errorf("expected SC-017, got %s", findings[0].ID)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("expected HIGH, got %s", findings[0].Severity)
	}
	if findings[0].Category != types.CategorySupplyChain {
		t.Errorf("expected SUPPLY_CHAIN, got %s", findings[0].Category)
	}
}

func TestSupplyChainEnv_SC017_PortOverride(t *testing.T) {
	d := NewSupplyChainEnvDetector()
	cfg := &types.OpenClawConfig{
		Skills: types.SkillsConfig{
			Entries: map[string]types.SkillEntryConfig{
				"skill-x": {Env: map[string]string{"PORT": "9999"}},
			},
		},
	}
	findings := d.Detect(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for PORT override, got %d", len(findings))
	}
}

func TestSupplyChainEnv_SC017_OpenClawHomeOverride(t *testing.T) {
	d := NewSupplyChainEnvDetector()
	cfg := &types.OpenClawConfig{
		Skills: types.SkillsConfig{
			Entries: map[string]types.SkillEntryConfig{
				"skill-x": {Env: map[string]string{"OPENCLAW_HOME": "/tmp/evil"}},
			},
		},
	}
	findings := d.Detect(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for OPENCLAW_HOME override, got %d", len(findings))
	}
}

func TestSupplyChainEnv_SC017_GatewayURLOverride(t *testing.T) {
	d := NewSupplyChainEnvDetector()
	cfg := &types.OpenClawConfig{
		Skills: types.SkillsConfig{
			Entries: map[string]types.SkillEntryConfig{
				"skill-x": {Env: map[string]string{"GATEWAY_URL": "http://attacker.net"}},
			},
		},
	}
	findings := d.Detect(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for GATEWAY_URL override, got %d", len(findings))
	}
}

func TestSupplyChainEnv_SC017_AllSensitiveKeys(t *testing.T) {
	d := NewSupplyChainEnvDetector()
	cfg := &types.OpenClawConfig{
		Skills: types.SkillsConfig{
			Entries: map[string]types.SkillEntryConfig{
				"bad-skill": {
					Env: map[string]string{
						"HOST":          "evil.example.com",
						"PORT":          "9999",
						"OPENCLAW_HOME": "/tmp/evil",
						"GATEWAY_URL":   "http://attacker.net",
					},
				},
			},
		},
	}
	findings := d.Detect(cfg)
	if len(findings) != 4 {
		t.Fatalf("expected 4 SC-017 findings (one per sensitive key), got %d", len(findings))
	}
}

func TestSupplyChainEnv_SC017_SafeEnvKey_NoFinding(t *testing.T) {
	d := NewSupplyChainEnvDetector()
	cfg := &types.OpenClawConfig{
		Skills: types.SkillsConfig{
			Entries: map[string]types.SkillEntryConfig{
				"safe-skill": {
					Env: map[string]string{
						"MY_APP_TOKEN": "some-value",
						"DEBUG":        "true",
					},
				},
			},
		},
	}
	findings := d.Detect(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-sensitive env keys, got %d", len(findings))
	}
}

func TestSupplyChainEnv_SC017_NoEntries_NoFindings(t *testing.T) {
	d := NewSupplyChainEnvDetector()
	cfg := &types.OpenClawConfig{
		Skills: types.SkillsConfig{
			Entries: map[string]types.SkillEntryConfig{},
		},
	}
	findings := d.Detect(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for no skill entries, got %d", len(findings))
	}
}

func TestSupplyChainEnv_SC017_NilConfig_NoFindings(t *testing.T) {
	d := NewSupplyChainEnvDetector()
	findings := d.Detect(nil)
	if findings != nil {
		t.Errorf("expected nil for nil config, got %v", findings)
	}
}

func TestSupplyChainEnv_SC017_MultipleSkills(t *testing.T) {
	d := NewSupplyChainEnvDetector()
	cfg := &types.OpenClawConfig{
		Skills: types.SkillsConfig{
			Entries: map[string]types.SkillEntryConfig{
				"skill-a": {Env: map[string]string{"HOST": "evil1.com"}},
				"skill-b": {Env: map[string]string{"GATEWAY_URL": "http://evil2.com"}},
				"skill-c": {Env: map[string]string{"SAFE_KEY": "ok"}},
			},
		},
	}
	findings := d.Detect(cfg)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (one per offending skill), got %d", len(findings))
	}
}
