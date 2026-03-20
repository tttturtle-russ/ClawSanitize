package types

import (
	"strings"
)

// RedactSecret preserves secret type while hiding value to prevent secondary leakage
func RedactSecret(secret string) string {
	// AWS Access Keys
	if strings.HasPrefix(secret, "AKIA") ||
		strings.HasPrefix(secret, "AGPA") ||
		strings.HasPrefix(secret, "AIDA") ||
		strings.HasPrefix(secret, "AROA") ||
		strings.HasPrefix(secret, "AIPA") ||
		strings.HasPrefix(secret, "ANPA") ||
		strings.HasPrefix(secret, "ANVA") ||
		strings.HasPrefix(secret, "ASIA") {
		return secret[:4] + "****"
	}

	// Anthropic Claude
	if strings.HasPrefix(secret, "sk-ant-") {
		return "sk-ant-****"
	}

	// OpenAI Project Keys
	if strings.HasPrefix(secret, "sk-proj-") {
		return "sk-proj-****"
	}

	// OpenAI Standard Keys
	if strings.HasPrefix(secret, "sk-") {
		return "sk-****"
	}

	// Slack Bot Tokens
	if strings.HasPrefix(secret, "xoxb-") {
		return "xoxb-****"
	}

	// Slack User Tokens
	if strings.HasPrefix(secret, "xoxp-") {
		return "xoxp-****"
	}

	// Slack App Tokens
	if strings.HasPrefix(secret, "xoxr-") {
		return "xoxr-****"
	}

	// Slack Signing Secret
	if strings.HasPrefix(secret, "xoxs-") {
		return "xoxs-****"
	}

	// GitHub Tokens
	if strings.HasPrefix(secret, "ghp_") {
		return "ghp_****"
	}
	if strings.HasPrefix(secret, "gho_") {
		return "gho_****"
	}
	if strings.HasPrefix(secret, "github_pat_") {
		return "github_pat_****"
	}

	// NPM Tokens
	if strings.HasPrefix(secret, "npm_") {
		return "npm_****"
	}

	// Stripe Keys
	if strings.HasPrefix(secret, "sk_live_") {
		return "sk_live_****"
	}
	if strings.HasPrefix(secret, "pk_live_") {
		return "pk_live_****"
	}
	if strings.HasPrefix(secret, "sk_test_") {
		return "sk_test_****"
	}
	if strings.HasPrefix(secret, "pk_test_") {
		return "pk_test_****"
	}

	// Google API Keys
	if strings.HasPrefix(secret, "AIza") && len(secret) >= 39 {
		return "AIza****"
	}

	// JWT Tokens
	if strings.HasPrefix(secret, "eyJ") && strings.Count(secret, ".") == 2 {
		return "eyJ****"
	}

	// Private Key Blocks
	if strings.Contains(secret, "-----BEGIN") && strings.Contains(secret, "PRIVATE KEY") {
		keyType := "PRIVATE KEY"
		if strings.Contains(secret, "RSA") {
			keyType = "RSA PRIVATE KEY"
		} else if strings.Contains(secret, "EC") {
			keyType = "EC PRIVATE KEY"
		} else if strings.Contains(secret, "DSA") {
			keyType = "DSA PRIVATE KEY"
		} else if strings.Contains(secret, "OPENSSH") {
			keyType = "OPENSSH PRIVATE KEY"
		}
		return "-----BEGIN " + keyType + "----- [REDACTED]"
	}

	// Generic: First 4 chars + ****
	if len(secret) > 8 {
		return secret[:4] + "****"
	}

	// Very short secrets: just mask
	return "****"
}
