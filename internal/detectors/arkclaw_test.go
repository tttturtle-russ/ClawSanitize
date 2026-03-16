package detectors

import (
	"testing"

	"github.com/tttturtle-russ/clawsan/internal/types"
)

func makeArkClawConfig(apiKey string) *types.OpenClawConfig {
	return &types.OpenClawConfig{
		Models: types.ModelsConfig{
			Providers: map[string]types.ModelProviderConfig{
				arkClawProviderKey: {ApiKey: apiKey},
			},
		},
	}
}

func TestArkClaw_Arkclaw001_ApiKey(t *testing.T) {
	d := NewArkClawDetector()
	cfg := makeArkClawConfig("ark-api-key-secret-12345")
	findings := d.Detect(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 ARKCLAW-001 finding, got %d", len(findings))
	}
	if findings[0].ID != "ARKCLAW-001" {
		t.Errorf("expected ARKCLAW-001, got %s", findings[0].ID)
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", findings[0].Severity)
	}
	if findings[0].Category != types.CategoryArkClaw {
		t.Errorf("expected category ARKCLAW, got %s", findings[0].Category)
	}
}

func TestArkClaw_EmptyApiKey_NoFinding(t *testing.T) {
	d := NewArkClawDetector()
	cfg := makeArkClawConfig("")
	findings := d.Detect(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty apiKey, got %d", len(findings))
	}
}

func TestArkClaw_NoProvider_NoFinding(t *testing.T) {
	d := NewArkClawDetector()
	cfg := &types.OpenClawConfig{
		Models: types.ModelsConfig{
			Providers: map[string]types.ModelProviderConfig{},
		},
	}
	findings := d.Detect(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when volcengine provider absent, got %d", len(findings))
	}
}

func TestArkClaw_NilConfig_NoFindings(t *testing.T) {
	d := NewArkClawDetector()
	findings := d.Detect(nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil config, got %d", len(findings))
	}
}

func TestArkClaw_FindingHasReference(t *testing.T) {
	d := NewArkClawDetector()
	cfg := makeArkClawConfig("some-key")
	findings := d.Detect(cfg)
	if len(findings) == 0 {
		t.Fatal("no findings returned")
	}
	if len(findings[0].References) == 0 {
		t.Error("ARKCLAW-001 should include at least one reference URL")
	}
}

func TestArkClaw_OtherProvider_NoFinding(t *testing.T) {
	d := NewArkClawDetector()
	cfg := &types.OpenClawConfig{
		Models: types.ModelsConfig{
			Providers: map[string]types.ModelProviderConfig{
				"openai": {ApiKey: "sk-some-key"},
			},
		},
	}
	findings := d.Detect(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-volcengine provider, got %d", len(findings))
	}
}
