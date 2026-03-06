package detectors

import (
	"testing"

	"github.com/tttturtle-russ/clawsan/internal/types"
)

func TestConfiguration_VulnerableConfig_AllFindings(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{
		DangerouslySkipPermissions: true,
		DMPolicy:                   "open",
		AllowFrom:                  []string{"*"},
		WorkspaceDir:               "/",
		APIKey:                     "sk-1234567890abcdef1234567890abcdef",
		Gateway:                    types.GatewayConfig{Bind: "0.0.0.0", Auth: false},
		Tailscale:                  types.TailscaleConfig{Enabled: true, Auth: false},
		SSH:                        types.SSHConfig{Enabled: false, Auth: false},
	}
	findings := d.Detect(cfg)
	if len(findings) < 6 {
		t.Errorf("expected at least 6 findings from vulnerable config, got %d", len(findings))
		for _, f := range findings {
			t.Logf("Found: %s - %s", f.ID, f.Title)
		}
	}
}

func TestConfiguration_C1_DangerouslySkipPermissions(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{DangerouslySkipPermissions: true}
	f := d.checkC1DangerouslySkipPermissions(cfg)
	if f == nil {
		t.Fatal("expected finding, got nil")
	}
	if f.ID != "CONFIG-001" {
		t.Errorf("expected CONFIG-001, got %s", f.ID)
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", f.Severity)
	}
}

func TestConfiguration_C1_SafeConfig(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{DangerouslySkipPermissions: false}
	f := d.checkC1DangerouslySkipPermissions(cfg)
	if f != nil {
		t.Error("expected nil finding for safe config, got finding")
	}
}

func TestConfiguration_C5_GatewayBinding(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{Gateway: types.GatewayConfig{Bind: "0.0.0.0"}}
	f := d.checkC5GatewayBinding(cfg)
	if f == nil {
		t.Fatal("expected finding for 0.0.0.0 binding")
	}
	if f.ID != "CONFIG-005" {
		t.Errorf("expected CONFIG-005, got %s", f.ID)
	}
}

func TestConfiguration_CleanConfig_NoFindings(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{
		DangerouslySkipPermissions: false,
		DMPolicy:                   "closed",
		WorkspaceDir:               "~/.openclaw/workspace",
		APIKey:                     "",
		Gateway:                    types.GatewayConfig{Bind: "127.0.0.1", Auth: true},
		Tailscale:                  types.TailscaleConfig{Enabled: false, Auth: true},
		SSH:                        types.SSHConfig{Enabled: false, Auth: true},
	}
	findings := d.Detect(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean config, got %d", len(findings))
		for _, f := range findings {
			t.Logf("Unexpected: %s - %s", f.ID, f.Title)
		}
	}
}

func TestConfig_S4_NoAPIKey(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{APIKey: ""}
	f := d.checkC4APIKeyInConfig(cfg)
	if f != nil {
		t.Errorf("expected nil finding for empty APIKey, got %s", f.ID)
	}
}

func TestConfig_C6_GatewayAuthEnabled(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{Gateway: types.GatewayConfig{Auth: true}}
	f := d.checkC6GatewayAuth(cfg)
	if f != nil {
		t.Errorf("expected nil finding when Auth is true, got %s", f.ID)
	}
}

func TestConfig_AllClean(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{
		DangerouslySkipPermissions: false,
		DMPolicy:                   "closed",
		WorkspaceDir:               "~/.openclaw/workspace",
		APIKey:                     "",
		Gateway:                    types.GatewayConfig{Bind: "127.0.0.1", Auth: true},
		Tailscale:                  types.TailscaleConfig{Enabled: false, Auth: true},
		SSH:                        types.SSHConfig{Enabled: false, Auth: true},
	}
	findings := d.Detect(cfg)
	if len(findings) != 0 {
		t.Errorf("expected zero findings for fully clean config, got %d", len(findings))
		for _, f := range findings {
			t.Logf("Unexpected finding: %s - %s", f.ID, f.Title)
		}
	}
}

func TestConfiguration_NilConfig_NoFindings(t *testing.T) {
	d := NewConfigurationDetector()
	findings := d.Detect(nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil config, got %d", len(findings))
	}
}

func TestConfiguration_EmptyConfig_HasExpectedFindings(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{}
	findings := d.Detect(cfg)
	hasC6 := false
	for _, f := range findings {
		if f.ID == "CONFIG-006" {
			hasC6 = true
		}
	}
	if !hasC6 {
		t.Errorf("expected CONFIG-006 from zero-value config (Auth defaults to false), got findings: %v", findings)
	}
}

func TestConfiguration_C4_APIKeyDetection(t *testing.T) {
	d := NewConfigurationDetector()
	cfg := &types.OpenClawConfig{APIKey: "sk-1234567890abcdef1234567890abcdef"}
	f := d.checkC4APIKeyInConfig(cfg)
	if f == nil {
		t.Fatal("expected CONFIG-004 finding for plausible API key, got nil")
	}
	if f.ID != "CONFIG-004" {
		t.Errorf("expected CONFIG-004, got %s", f.ID)
	}
	if f.Severity != types.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
}
