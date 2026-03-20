package types

import (
	"strings"
	"testing"
)

func TestRedactSecret(t *testing.T) {
	tests := []struct {
		name     string
		secret   string
		expected string
	}{
		{"AWS Key AKIA", "AKIAIOSFODNN7EXAMPLE", "AKIA****"},
		{"AWS Key AGPA", "AGPA1234567890ABCDEF", "AGPA****"},
		{"AWS Key AIDA", "AIDA1234567890ABCDEF", "AIDA****"},
		{"Anthropic", "sk-ant-api03-AbCdEf123456", "sk-ant-****"},
		{"OpenAI Project", "sk-proj-1234567890AbCdEf", "sk-proj-****"},
		{"OpenAI Standard", "sk-1234567890AbCdEf", "sk-****"},
		{"Slack Bot", "xoxb-1234567890-AbCdEf", "xoxb-****"},
		{"Slack User", "xoxp-1234567890-AbCdEf", "xoxp-****"},
		{"Slack App", "xoxr-1234567890-AbCdEf", "xoxr-****"},
		{"Slack Signing", "xoxs-1234567890-AbCdEf", "xoxs-****"},
		{"GitHub PAT", "ghp_1234567890AbCdEf", "ghp_****"},
		{"GitHub OAuth", "gho_1234567890AbCdEf", "gho_****"},
		{"GitHub PAT New", "github_pat_1234567890AbCdEf", "github_pat_****"},
		{"NPM Token", "npm_1234567890AbCdEf", "npm_****"},
		{"Stripe Live Secret", "sk_live_1234567890AbCdEf", "sk_live_****"},
		{"Stripe Live Publishable", "pk_live_1234567890AbCdEf", "pk_live_****"},
		{"Stripe Test Secret", "sk_test_1234567890AbCdEf", "sk_test_****"},
		{"Stripe Test Publishable", "pk_test_1234567890AbCdEf", "pk_test_****"},
		{"Google API Key", "AIzaSyD1234567890AbCdEf1234567890123456", "AIza****"},
		{"JWT", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "eyJ****"},
		{"RSA Private Key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY----- [REDACTED]"},
		{"EC Private Key", "-----BEGIN EC PRIVATE KEY-----\nMHc...\n-----END EC PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY----- [REDACTED]"},
		{"Generic Private Key", "-----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY-----", "-----BEGIN PRIVATE KEY----- [REDACTED]"},
		{"OPENSSH Private Key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blb...\n-----END OPENSSH PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY----- [REDACTED]"},
		{"Generic Long", "verylongsecretkey1234567890", "very****"},
		{"Generic Short", "short", "****"},
		{"Empty", "", "****"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactSecret(tt.secret)
			if got != tt.expected {
				t.Errorf("RedactSecret() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestRedactSecret_PreservesPrefix(t *testing.T) {
	tests := []struct {
		secret       string
		wantPrefix   string
		wantContains string
	}{
		{"AKIAIOSFODNN7EXAMPLE123456", "AKIA", "****"},
		{"sk-ant-api03-real-secret-key", "sk-ant-", "****"},
		{"ghp_AbCdEf1234567890", "ghp_", "****"},
	}

	for _, tt := range tests {
		t.Run(tt.secret[:min(15, len(tt.secret))], func(t *testing.T) {
			got := RedactSecret(tt.secret)

			if !strings.HasPrefix(got, tt.wantPrefix) {
				t.Errorf("RedactSecret() = %q, want prefix %q", got, tt.wantPrefix)
			}

			if !strings.Contains(got, tt.wantContains) {
				t.Errorf("RedactSecret() = %q, want to contain %q", got, tt.wantContains)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
