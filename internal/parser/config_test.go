package parser

import (
	"testing"

	"github.com/yourusername/clawsanitizer/internal/types"
)

func TestParseConfig_Vulnerable(t *testing.T) {
	cfg, err := ParseConfig("../../testdata/vulnerable-config")
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}
	if !cfg.DangerouslySkipPermissions {
		t.Error("expected dangerously_skip_permissions=true")
	}
	if cfg.DMPolicy != "open" {
		t.Errorf("expected dmPolicy=open, got %s", cfg.DMPolicy)
	}
	if cfg.Gateway.Bind != "0.0.0.0" {
		t.Errorf("expected gateway.bind=0.0.0.0, got %s", cfg.Gateway.Bind)
	}
}

func TestParseConfig_Clean(t *testing.T) {
	cfg, err := ParseConfig("../../testdata/clean-config")
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}
	if cfg.DangerouslySkipPermissions {
		t.Error("expected dangerously_skip_permissions=false")
	}
	if cfg.DMPolicy != "closed" {
		t.Errorf("expected dmPolicy=closed, got %s", cfg.DMPolicy)
	}
}

func TestParseConfig_MissingFile(t *testing.T) {
	_, err := ParseConfig("/nonexistent/path")
	if err == nil {
		t.Error("expected error for missing config file, got nil")
	}
}

func TestOpenClawConfig_Fields(t *testing.T) {
	cfg := types.OpenClawConfig{}
	_ = cfg.DangerouslySkipPermissions
	_ = cfg.DMPolicy
	_ = cfg.Gateway.Bind
	_ = cfg.Gateway.Auth
}
