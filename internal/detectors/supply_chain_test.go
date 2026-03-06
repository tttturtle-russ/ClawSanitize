package detectors

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tttturtle-russ/clawsan/internal/api"
	"github.com/tttturtle-russ/clawsan/internal/types"
)

func makeTestSupplyChainDetector(server *httptest.Server) *SupplyChainDetector {
	client := api.NewClawHubClient()
	if server != nil {
		client.BaseURL = server.URL
	}
	return &SupplyChainDetector{ClawHub: client}
}

// skillHandler returns an httptest handler that serves:
//
//	GET /skills/{slug}           → skillBody
//	GET /skills/{slug}/versions/* → versionBody (if non-empty)
func skillHandler(skillBody, versionBody string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 && parts[2] == "versions" && versionBody != "" {
			w.Write([]byte(versionBody))
			return
		}
		w.Write([]byte(skillBody))
	}
}

func TestSupplyChain_S1_MissingHash(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "my-skill", Source: "clawhub://my-skill@1.0.0", Hash: ""},
		},
	}
	findings := d.checkS1HashVerification(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "SUPPLY_CHAIN-001" {
		t.Errorf("expected ID SUPPLY_CHAIN-001, got %s", findings[0].ID)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
}

func TestSupplyChain_S2_MaliciousSkill(t *testing.T) {
	skillBody := `{"skill":{"slug":"evil-skill","displayName":"Evil Skill"},"latestVersion":{"version":"1.0.0"},"moderation":{"isMalwareBlocked":true,"isSuspicious":false}}`
	server := httptest.NewServer(skillHandler(skillBody, ""))
	defer server.Close()

	d := makeTestSupplyChainDetector(server)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "evil-skill", Source: "clawhub://evil-skill@1.0.0", Hash: "abc123"},
		},
	}
	findings := d.checkS2ClawHubReputation(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "SUPPLY_CHAIN-002" {
		t.Errorf("expected ID SUPPLY_CHAIN-002, got %s", findings[0].ID)
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", findings[0].Severity)
	}
}

func TestSupplyChain_S2_SuspiciousSkill(t *testing.T) {
	skillBody := `{"skill":{"slug":"feed-watcher","displayName":"Feed Watcher"},"latestVersion":{"version":"1.2.0"},"moderation":null}`
	versionBody := `{"version":{"version":"1.2.0","security":{"status":"suspicious","hasWarnings":true,"checkedAt":1772465516623,"model":"gpt-5-mini"}}}`
	server := httptest.NewServer(skillHandler(skillBody, versionBody))
	defer server.Close()

	d := makeTestSupplyChainDetector(server)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "feed-watcher", Source: "clawhub://feed-watcher@1.2.0", Hash: "abc123"},
		},
	}
	findings := d.checkS2ClawHubReputation(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for suspicious skill, got %d", len(findings))
	}
	if findings[0].ID != "SUPPLY_CHAIN-002B" {
		t.Errorf("expected ID SUPPLY_CHAIN-002B, got %s", findings[0].ID)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("expected HIGH severity for suspicious skill, got %s", findings[0].Severity)
	}
}

func TestSupplyChain_S2_MaliciousViaSecurityStatus(t *testing.T) {
	skillBody := `{"skill":{"slug":"data-harvester-v2","displayName":"Data Harvester"},"latestVersion":{"version":"2.0.0"},"moderation":null}`
	versionBody := `{"version":{"version":"2.0.0","security":{"status":"malicious","hasWarnings":true,"checkedAt":1772465516623,"model":"gpt-5-mini"}}}`
	server := httptest.NewServer(skillHandler(skillBody, versionBody))
	defer server.Close()

	d := makeTestSupplyChainDetector(server)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "data-harvester-v2", Source: "clawhub://data-harvester-v2@2.0.0", Hash: "abc123"},
		},
	}
	findings := d.checkS2ClawHubReputation(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for malicious security status, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", findings[0].Severity)
	}
}

func TestSupplyChain_S2_OfflineFallback(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "skill-a", Source: "clawhub://skill-a@1.0.0", Hash: "abc"},
		},
	}
	findings := d.checkS2ClawHubReputation(cfg)
	if len(findings) != 0 {
		t.Errorf("offline should produce 0 findings, got %d", len(findings))
	}
}

func TestSupplyChain_S3_UnofficialSource(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "my-skill", Source: "https://github.com/unknown/my-skill", Hash: "abc"},
		},
	}
	findings := d.checkS3UnofficialSources(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "SUPPLY_CHAIN-003" {
		t.Errorf("expected SUPPLY_CHAIN-003, got %s", findings[0].ID)
	}
}

func TestSupplyChain_NoSkills(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	cfg := &types.OpenClawConfig{Skills: []types.SkillConfig{}}
	findings := d.Detect(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty skills, got %d", len(findings))
	}
}

func TestSupplyChain_S1_HashMismatch(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "suspicious-skill", Source: "clawhub://suspicious-skill@2.0.0", Hash: ""},
		},
	}
	findings := d.checkS1HashVerification(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for skill with no hash, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "SUPPLY_CHAIN-001" {
		t.Errorf("expected ID SUPPLY_CHAIN-001, got %s", f.ID)
	}
	if f.Severity != types.SeverityHigh {
		t.Errorf("expected severity HIGH, got %s", f.Severity)
	}
	if f.Category != types.CategorySupplyChain {
		t.Errorf("expected category %s, got %s", types.CategorySupplyChain, f.Category)
	}
}

func TestSupplyChain_S1_WithHash(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "safe-skill", Source: "clawhub://safe-skill@1.0.0", Hash: "sha256:abc123def456"},
		},
	}
	findings := d.checkS1HashVerification(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for skill with hash, got %d", len(findings))
	}
}

func TestSupplyChain_S2_OfflineGracefulFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Close()

	client := api.NewClawHubClient()
	client.BaseURL = server.URL
	d := &SupplyChainDetector{ClawHub: client}

	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "any-skill", Source: "clawhub://any-skill@1.0.0", Hash: "abc"},
		},
	}
	findings := d.checkS2ClawHubReputation(cfg)
	if len(findings) != 0 {
		t.Errorf("offline fallback should produce 0 findings, got %d", len(findings))
	}
}

func TestSupplyChain_S2_CleanSkill(t *testing.T) {
	skillBody := `{"skill":{"slug":"clean-skill","displayName":"Clean Skill"},"latestVersion":{"version":"1.0.0"},"moderation":null}`
	versionBody := `{"version":{"version":"1.0.0","security":{"status":"clean","hasWarnings":false,"checkedAt":1772465516623,"model":"gpt-5-mini"}}}`
	server := httptest.NewServer(skillHandler(skillBody, versionBody))
	defer server.Close()

	d := makeTestSupplyChainDetector(server)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "clean-skill", Source: "clawhub://clean-skill@1.0.0", Hash: "abc123"},
		},
	}
	findings := d.checkS2ClawHubReputation(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean skill, got %d", len(findings))
	}
}

func TestSupplyChain_S3_UnofficialSource_WithSeverity(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "github-skill", Source: "https://github.com/random/skill", Hash: "abc"},
		},
	}
	findings := d.checkS3UnofficialSources(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unofficial source, got %d", len(findings))
	}
	if findings[0].ID != "SUPPLY_CHAIN-003" {
		t.Errorf("expected ID SUPPLY_CHAIN-003, got %s", findings[0].ID)
	}
	if findings[0].Severity != types.SeverityMedium {
		t.Errorf("expected severity MEDIUM, got %s", findings[0].Severity)
	}
}

func TestSupplyChain_CleanConfig_NoFindings(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "official-skill", Source: "clawhub://official-skill@3.1.0", Hash: "sha256:deadbeef"},
		},
	}
	findings := d.checkS3UnofficialSources(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 S3 findings for official clawhub source, got %d", len(findings))
	}
}

func TestSupplyChain_S3_EmptySource(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "no-source-skill", Source: "", Hash: "abc"},
		},
	}
	findings := d.checkS3UnofficialSources(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for skill with empty source, got %d", len(findings))
	}
}

func TestSupplyChain_S4_DangerousNameUnofficialSource(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "shell-runner", Source: "https://github.com/hacker/shell-runner", Hash: "abc"},
		},
	}
	findings := d.checkS4EmptyHashes(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for dangerous-named unofficial skill, got %d", len(findings))
	}
	if findings[0].ID != "SUPPLY_CHAIN-004" {
		t.Errorf("expected ID SUPPLY_CHAIN-004, got %s", findings[0].ID)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("expected severity HIGH, got %s", findings[0].Severity)
	}
}

func TestSupplyChain_S4_DangerousNameOfficialSource(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "exec-helper", Source: "clawhub://exec-helper@1.0.0", Hash: "abc"},
		},
	}
	findings := d.checkS4EmptyHashes(cfg)
	if len(findings) != 0 {
		t.Errorf("official-source dangerous-named skill should not trigger S4, got %d findings", len(findings))
	}
}

func TestSupplyChain_S4_AllDangerousKeywords(t *testing.T) {
	keywords := []string{"shell", "exec", "execute", "root", "sudo", "admin", "system"}
	for _, kw := range keywords {
		kw := kw
		t.Run(kw, func(t *testing.T) {
			d := makeTestSupplyChainDetector(nil)
			cfg := &types.OpenClawConfig{
				Skills: []types.SkillConfig{
					{Name: kw + "-tool", Source: "https://evil.example.com/" + kw, Hash: "abc"},
				},
			}
			findings := d.checkS4EmptyHashes(cfg)
			if len(findings) != 1 {
				t.Errorf("keyword %q: expected 1 finding, got %d", kw, len(findings))
			}
		})
	}
}

func TestSupplyChain_FindingHasCorrectFields(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "untrusted-skill", Source: "https://github.com/random/untrusted-skill", Hash: ""},
		},
	}
	findings := d.Detect(cfg)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding but got none")
	}
	for _, f := range findings {
		if f.ID == "" {
			t.Errorf("finding ID must not be empty")
		}
		if f.Severity == "" {
			t.Errorf("finding Severity must not be empty (ID=%s)", f.ID)
		}
		if f.Category == "" {
			t.Errorf("finding Category must not be empty (ID=%s)", f.ID)
		}
		if f.Title == "" {
			t.Errorf("finding Title must not be empty (ID=%s)", f.ID)
		}
		if f.Description == "" {
			t.Errorf("finding Description must not be empty (ID=%s)", f.ID)
		}
		if f.Remediation == "" {
			t.Errorf("finding Remediation must not be empty (ID=%s)", f.ID)
		}
	}
}

func TestSupplyChain_MultipleSkills(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "skill-a", Source: "https://github.com/x/skill-a", Hash: ""},
			{Name: "skill-b", Source: "clawhub://skill-b@1.0.0", Hash: "abc123"},
			{Name: "skill-c", Source: "https://github.com/x/skill-c", Hash: "xyz"},
		},
	}
	s1Findings := d.checkS1HashVerification(cfg)
	if len(s1Findings) != 1 {
		t.Errorf("expected 1 S1 finding (skill-a), got %d", len(s1Findings))
	}
	s3Findings := d.checkS3UnofficialSources(cfg)
	if len(s3Findings) != 2 {
		t.Errorf("expected 2 S3 findings (skill-a, skill-c), got %d", len(s3Findings))
	}
}

func TestSupplyChain_S4_NoSkills(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	cfg := &types.OpenClawConfig{Skills: []types.SkillConfig{}}
	findings := d.checkS4EmptyHashes(cfg)
	if findings != nil {
		t.Errorf("expected nil findings for empty skills, got %v", findings)
	}
}

func TestSupplyChain_S2_KnownBadSkill(t *testing.T) {
	const skillName = "credential-harvester"

	skillBody := fmt.Sprintf(`{"skill":{"slug":%q,"displayName":%q},"latestVersion":{"version":"0.1.0"},"moderation":{"isMalwareBlocked":true,"isSuspicious":false}}`, skillName, skillName)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, skillName) {
			t.Errorf("unexpected request path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(skillBody))
	}))
	defer server.Close()

	d := makeTestSupplyChainDetector(server)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: skillName, Source: "clawhub://" + skillName + "@0.1.0", Hash: "somehash"},
		},
	}
	findings := d.checkS2ClawHubReputation(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for known-bad skill, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "SUPPLY_CHAIN-002" {
		t.Errorf("wrong ID: %s, want SUPPLY_CHAIN-002", f.ID)
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("wrong severity: %s, want CRITICAL", f.Severity)
	}
	if f.Category != types.CategorySupplyChain {
		t.Errorf("wrong category: %s", f.Category)
	}
	if !strings.Contains(f.Title, skillName) {
		t.Errorf("title should mention skill name %q, got: %s", skillName, f.Title)
	}
}

func TestSupplyChain_S4_NoFindings_CleanConfig(t *testing.T) {
	d := makeTestSupplyChainDetector(nil)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "markdown-helper", Source: "clawhub://markdown-helper@1.0.0", Hash: "sha256:abc"},
			{Name: "git-assistant", Source: "clawhub://git-assistant@2.1.0", Hash: "sha256:def"},
		},
	}
	findings := d.checkS4EmptyHashes(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 S4 findings for clean official-source config, got %d", len(findings))
	}
}

func TestSupplyChain_FindingIDs(t *testing.T) {
	skillBody := `{"skill":{"slug":"shell-evil","displayName":"Shell Evil"},"latestVersion":{"version":"1.0.0"},"moderation":{"isMalwareBlocked":true,"isSuspicious":false}}`
	server := httptest.NewServer(skillHandler(skillBody, ""))
	defer server.Close()

	d := makeTestSupplyChainDetector(server)
	cfg := &types.OpenClawConfig{
		Skills: []types.SkillConfig{
			{Name: "shell-evil", Source: "https://github.com/bad/shell-evil", Hash: ""},
		},
	}
	findings := d.Detect(cfg)

	validIDs := map[string]bool{
		"SUPPLY_CHAIN-001":  false,
		"SUPPLY_CHAIN-002":  false,
		"SUPPLY_CHAIN-003":  false,
		"SUPPLY_CHAIN-004":  false,
		"SUPPLY_CHAIN-002B": true,
	}

	for _, f := range findings {
		if _, ok := validIDs[f.ID]; !ok {
			t.Errorf("unexpected finding ID: %s", f.ID)
		}
		validIDs[f.ID] = true
		if f.Category == "" {
			t.Errorf("finding %s has empty category", f.ID)
		}
		if f.Title == "" {
			t.Errorf("finding %s has empty title", f.ID)
		}
		if f.Remediation == "" {
			t.Errorf("finding %s has empty remediation", f.ID)
		}
	}

	for id, seen := range validIDs {
		if !seen {
			t.Errorf("expected finding %s was not produced", id)
		}
	}
}
