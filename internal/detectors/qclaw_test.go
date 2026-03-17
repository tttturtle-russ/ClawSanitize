package detectors

import (
	"testing"

	"github.com/tttturtle-russ/ClawSanitizer/internal/types"
)

func makeQClawConfig(jwt, channelToken, apiKey string) *types.OpenClawConfig {
	creds := &types.QClawCredentials{
		JwtToken:     jwt,
		ChannelToken: channelToken,
		ApiKey:       apiKey,
	}
	return &types.OpenClawConfig{
		Channels: map[string]types.ChannelConfig{
			qclawChannelKey: {QClaw: creds},
		},
	}
}

func TestQClaw_Qclaw001_JwtToken(t *testing.T) {
	d := NewQClawDetector()
	cfg := makeQClawConfig("eyJhbGciOiJIUzI1NiJ9.payload.sig", "", "")
	findings := d.Detect(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for jwtToken, got %d", len(findings))
	}
	if findings[0].ID != "QCLAW-001" {
		t.Errorf("expected QCLAW-001, got %s", findings[0].ID)
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", findings[0].Severity)
	}
}

func TestQClaw_Qclaw002_ChannelToken(t *testing.T) {
	d := NewQClawDetector()
	cfg := makeQClawConfig("", "channel-token-secret", "")
	findings := d.Detect(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for channelToken, got %d", len(findings))
	}
	if findings[0].ID != "QCLAW-002" {
		t.Errorf("expected QCLAW-002, got %s", findings[0].ID)
	}
}

func TestQClaw_Qclaw003_ApiKey(t *testing.T) {
	d := NewQClawDetector()
	cfg := makeQClawConfig("", "", "qclaw-api-key-12345")
	findings := d.Detect(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for apiKey, got %d", len(findings))
	}
	if findings[0].ID != "QCLAW-003" {
		t.Errorf("expected QCLAW-003, got %s", findings[0].ID)
	}
}

func TestQClaw_AllThreeCredentials(t *testing.T) {
	d := NewQClawDetector()
	cfg := makeQClawConfig("jwt-token", "chan-token", "api-key")
	findings := d.Detect(cfg)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings when all credentials set, got %d", len(findings))
	}
}

func TestQClaw_NoChannel_NoFindings(t *testing.T) {
	d := NewQClawDetector()
	cfg := &types.OpenClawConfig{
		Channels: map[string]types.ChannelConfig{},
	}
	findings := d.Detect(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when channel absent, got %d", len(findings))
	}
}

func TestQClaw_NoQClawCredentials_NoFindings(t *testing.T) {
	d := NewQClawDetector()
	cfg := &types.OpenClawConfig{
		Channels: map[string]types.ChannelConfig{
			qclawChannelKey: {QClaw: nil},
		},
	}
	findings := d.Detect(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when qclaw creds nil, got %d", len(findings))
	}
}

func TestQClaw_EmptyCredentials_NoFindings(t *testing.T) {
	d := NewQClawDetector()
	cfg := makeQClawConfig("", "", "")
	findings := d.Detect(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty credentials, got %d", len(findings))
	}
}

func TestQClaw_NilConfig_NoFindings(t *testing.T) {
	d := NewQClawDetector()
	findings := d.Detect(nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil config, got %d", len(findings))
	}
}
