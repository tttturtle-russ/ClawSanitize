package detectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tttturtle-russ/clawsan/internal/parser"
	"github.com/tttturtle-russ/clawsan/internal/types"
)

func TestCredentialStorage_Cred001_InsecureDirPerms(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	d := NewCredentialStorageDetector()
	f := d.checkCred001DirPermissions(dir)
	if f == nil {
		t.Fatal("expected CRED-001 finding for world-readable dir, got nil")
	}
	if f.ID != "CRED-001" {
		t.Errorf("expected CRED-001, got %s", f.ID)
	}
	if f.Severity != types.SeverityHigh {
		t.Errorf("expected HIGH, got %s", f.Severity)
	}
}

func TestCredentialStorage_Cred001_SecureDirPerms(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	d := NewCredentialStorageDetector()
	f := d.checkCred001DirPermissions(dir)
	if f != nil {
		t.Errorf("expected nil for secure dir perms, got %s", f.ID)
	}
}

func TestCredentialStorage_Cred002_InsecureConfigPerms(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	if err := os.WriteFile(configPath, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	d := NewCredentialStorageDetector()
	f := d.checkCred002ConfigPermissions(dir)
	if f == nil {
		t.Fatal("expected CRED-002 finding for world-readable config, got nil")
	}
	if f.ID != "CRED-002" {
		t.Errorf("expected CRED-002, got %s", f.ID)
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", f.Severity)
	}
}

func TestCredentialStorage_Cred002_SecureConfigPerms(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	if err := os.WriteFile(configPath, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	d := NewCredentialStorageDetector()
	f := d.checkCred002ConfigPermissions(dir)
	if f != nil {
		t.Errorf("expected nil for secure config perms, got %s", f.ID)
	}
}

func TestCredentialStorage_Cred002_MissingConfig_NoFinding(t *testing.T) {
	dir := t.TempDir()
	d := NewCredentialStorageDetector()
	f := d.checkCred002ConfigPermissions(dir)
	if f != nil {
		t.Errorf("expected nil when config file absent, got %s", f.ID)
	}
}

func TestCredentialStorage_Cred007_ApiKeyInSoulMD(t *testing.T) {
	ws := &parser.WorkspaceData{
		SoulPath: "/fake/SOUL.md",
		SoulMD:   "sk-ant-api01-ABCDEFGHIJ1234567890abcdefghijklmnop",
	}
	d := NewCredentialStorageDetector()
	findings := d.checkCred007ApiKeysInMemoryFiles(ws)
	if len(findings) == 0 {
		t.Fatal("expected CRED-007 finding for API key in SOUL.md, got none")
	}
	if findings[0].ID != "CRED-007" {
		t.Errorf("expected CRED-007, got %s", findings[0].ID)
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", findings[0].Severity)
	}
}

func TestCredentialStorage_Cred007_NoKeyInFiles(t *testing.T) {
	ws := &parser.WorkspaceData{
		SoulPath: "/fake/SOUL.md",
		SoulMD:   "# Normal soul content\nNo credentials here.",
	}
	d := NewCredentialStorageDetector()
	findings := d.checkCred007ApiKeysInMemoryFiles(ws)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean files, got %d", len(findings))
	}
}

func TestCredentialStorage_Cred007_OpenAIKey(t *testing.T) {
	ws := &parser.WorkspaceData{
		MemoryPath: "/fake/MEMORY.md",
		MemoryMD:   "Use this key: sk-proj-ABCDEFGHIJ1234567890abcdefghijklmnop",
	}
	d := NewCredentialStorageDetector()
	findings := d.checkCred007ApiKeysInMemoryFiles(ws)
	if len(findings) == 0 {
		t.Fatal("expected CRED-007 for OpenAI project key in MEMORY.md")
	}
}

func TestCredentialStorage_NilWorkspace(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	d := NewCredentialStorageDetector()
	findings := d.Detect(dir, nil)
	for _, f := range findings {
		if f.ID == "CRED-007" {
			t.Error("should not check workspace keys when workspace is nil")
		}
	}
}
