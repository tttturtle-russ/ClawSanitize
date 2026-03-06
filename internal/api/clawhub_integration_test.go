//go:build integration

package api

import (
	"testing"
)

func TestCheckSkillReputation_RealAPI_KnownSkill_Polymarket(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	c := NewClawHubClient()
	info, err := c.CheckSkillReputation("polymarketodds")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("expected SkillInfo, got nil")
	}
	if !info.KnownToClawHub {
		t.Error("KnownToClawHub should be true for a real skill")
	}
	if info.Slug != "polymarketodds" {
		t.Errorf("unexpected Slug: %q, want %q", info.Slug, "polymarketodds")
	}
	if info.DisplayName == "" {
		t.Error("DisplayName should not be empty for a real skill")
	}
	if info.Malicious {
		t.Error("polymarketodds should not be flagged malicious")
	}
	if info.SecurityStatus == "" {
		t.Error("SecurityStatus should be populated after version fetch")
	}
}

func TestCheckSkillReputation_RealAPI_SuspiciousSkill_FeedWatcher(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	c := NewClawHubClient()
	info, err := c.CheckSkillReputation("feed-watcher")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("expected SkillInfo, got nil")
	}
	if !info.KnownToClawHub {
		t.Error("KnownToClawHub should be true for a real skill")
	}
	if info.Slug != "feed-watcher" {
		t.Errorf("unexpected Slug: %q, want %q", info.Slug, "feed-watcher")
	}
	if info.SecurityStatus != "suspicious" {
		t.Errorf("expected SecurityStatus %q, got %q", "suspicious", info.SecurityStatus)
	}
	if !info.IsSuspicious {
		t.Error("IsSuspicious should be true for feed-watcher")
	}
}

func TestCheckSkillReputation_RealAPI_UnknownSkill_Returns404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	c := NewClawHubClient()
	info, err := c.CheckSkillReputation("this-skill-does-not-exist-xyzzy-404")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("expected SkillInfo (not nil) for unknown skill")
	}
	if info.KnownToClawHub {
		t.Error("KnownToClawHub should be false for a non-existent skill")
	}
	if info.Malicious {
		t.Error("Malicious should be false for an unknown skill")
	}
}
