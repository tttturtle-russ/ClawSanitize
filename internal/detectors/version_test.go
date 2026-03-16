package detectors

import (
	"testing"

	"github.com/tttturtle-russ/clawsan/internal/types"
)

func TestVersion_VulnerableVersion_AllSixFindings(t *testing.T) {
	d := NewVersionDetector()
	cfg := &types.OpenClawConfig{
		Meta: types.MetaConfig{LastTouchedVersion: "2026.1.1"},
	}
	findings := d.Detect(cfg)
	if len(findings) != 6 {
		t.Errorf("expected 6 version findings for v2026.1.1, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  %s: %s", f.ID, f.Title)
		}
	}
}

func TestVersion_PatchedVersion_NoFindings(t *testing.T) {
	d := NewVersionDetector()
	cfg := &types.OpenClawConfig{
		Meta: types.MetaConfig{LastTouchedVersion: "2026.3.1"},
	}
	findings := d.Detect(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for patched version, got %d", len(findings))
	}
}

func TestVersion_Ver001_ClawJacked(t *testing.T) {
	d := NewVersionDetector()
	v, _ := parseSemver("2026.2.10")
	f := d.checkVer001ClawJackedWebSocket(v, "2026.2.10")
	if f == nil {
		t.Fatal("expected VER-001 for version before 2026.2.26")
	}
	if f.ID != "VER-001" {
		t.Errorf("expected VER-001, got %s", f.ID)
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", f.Severity)
	}
}

func TestVersion_Ver001_Patched(t *testing.T) {
	d := NewVersionDetector()
	v, _ := parseSemver("2026.2.26")
	f := d.checkVer001ClawJackedWebSocket(v, "2026.2.26")
	if f != nil {
		t.Errorf("expected nil for patched version 2026.2.26, got %s", f.ID)
	}
}

func TestVersion_Ver006_CronSSRF_VulnerableVersion(t *testing.T) {
	d := NewVersionDetector()
	v, _ := parseSemver("2026.2.15")
	f := d.checkVer006CVE202627488(v, "2026.2.15")
	if f == nil {
		t.Fatal("expected VER-006 for version before 2026.2.19")
	}
	if f.ID != "VER-006" {
		t.Errorf("expected VER-006, got %s", f.ID)
	}
}

func TestVersion_Ver006_CronSSRF_Patched(t *testing.T) {
	d := NewVersionDetector()
	v, _ := parseSemver("2026.2.19")
	f := d.checkVer006CVE202627488(v, "2026.2.19")
	if f != nil {
		t.Errorf("expected nil for patched version 2026.2.19, got %s", f.ID)
	}
}

func TestVersion_ParseSemver_Valid(t *testing.T) {
	v, ok := parseSemver("2026.2.14")
	if !ok {
		t.Fatal("parseSemver should succeed for '2026.2.14'")
	}
	if v.year != 2026 || v.month != 2 || v.patch != 14 {
		t.Errorf("unexpected parsed values: %+v", v)
	}
}

func TestVersion_ParseSemver_Invalid(t *testing.T) {
	cases := []string{"", "1.2", "a.b.c", "2026.2"}
	for _, c := range cases {
		_, ok := parseSemver(c)
		if ok {
			t.Errorf("parseSemver(%q) should fail, got ok=true", c)
		}
	}
}

func TestVersion_EmptyVersion_NoFindings(t *testing.T) {
	d := NewVersionDetector()
	cfg := &types.OpenClawConfig{
		Meta: types.MetaConfig{LastTouchedVersion: ""},
	}
	findings := d.Detect(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty version, got %d", len(findings))
	}
}

func TestVersion_NilConfig_NoFindings(t *testing.T) {
	d := NewVersionDetector()
	findings := d.Detect(nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil config, got %d", len(findings))
	}
}

func TestVersion_FindingsHaveReferences(t *testing.T) {
	d := NewVersionDetector()
	cfg := &types.OpenClawConfig{
		Meta: types.MetaConfig{LastTouchedVersion: "2026.1.1"},
	}
	findings := d.Detect(cfg)
	for _, f := range findings {
		if len(f.References) == 0 {
			t.Errorf("finding %s should have at least one reference", f.ID)
		}
	}
}
