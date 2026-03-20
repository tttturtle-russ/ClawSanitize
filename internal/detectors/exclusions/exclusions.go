package exclusions

import (
	"regexp"
)

// Checker provides multi-level exclusion logic to reduce false positives
type Checker struct {
	// Level 1: Placeholder/example markers
	placeholderPatterns []*regexp.Regexp

	// Level 2: Variable reference patterns
	variableRefPatterns []*regexp.Regexp

	// Level 3: Documentation context patterns
	documentationPatterns []*regexp.Regexp

	// Level 4: Negation context patterns
	negationPatterns []*regexp.Regexp

	// Level 5: Security tool patterns (avoid flagging our own examples)
	securityToolPatterns []*regexp.Regexp
}

// NewChecker creates a new exclusion checker with default patterns
func NewChecker() *Checker {
	return &Checker{
		placeholderPatterns: []*regexp.Regexp{
			// Generic placeholders
			regexp.MustCompile(`(?i)(example|placeholder|test_key|fake|demo|sample|mock|dummy)`),
			regexp.MustCompile(`(?i)(your_|my_|our_|their_)`),
			regexp.MustCompile(`(?i)(replace_with|fill_in|insert_|enter_your)`),

			// AWS examples
			regexp.MustCompile(`AKIAIOSFODNN7EXAMPLE`),
			regexp.MustCompile(`AKIAI44QH8DHBEXAMPLE`),
			regexp.MustCompile(`wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`),

			// OpenAI examples
			regexp.MustCompile(`sk-proj-[A-Za-z0-9_-]*EXAMPLE`),

			regexp.MustCompile(`^x{5,}$`),
			regexp.MustCompile(`^[0-9]{5,}$`),
			regexp.MustCompile(`^[a-z]{5,}$`),
		},

		variableRefPatterns: []*regexp.Regexp{
			// Shell-style
			regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}`), // ${API_KEY}
			regexp.MustCompile(`\$[A-Za-z_][A-Za-z0-9_]*`),     // $API_KEY
			regexp.MustCompile(`%[A-Za-z_][A-Za-z0-9_]*%`),     // %API_KEY%

			// Go
			regexp.MustCompile(`os\.Getenv\(['"][A-Za-z_][A-Za-z0-9_]*['"]\)`),

			// Python
			regexp.MustCompile(`os\.environ(?:\.get)?\(['"][A-Za-z_][A-Za-z0-9_]*['"]\)`),

			// JavaScript/TypeScript
			regexp.MustCompile(`process\.env\.[A-Za-z_][A-Za-z0-9_]*`),

			// Generic template syntax
			regexp.MustCompile(`\{\{[A-Za-z_][A-Za-z0-9_]*\}\}`), // {{API_KEY}}
			regexp.MustCompile(`<[A-Za-z_][A-Za-z0-9_]*>`),       // <API_KEY>
		},

		documentationPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(export|set)\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*[<\[]?(your|my|example)`),
			regexp.MustCompile(`(?i)(configure|setup|create|add|set).{0,30}(your|a|an).{0,30}(key|token|secret|password|api)`),
			regexp.MustCompile(`(?i)(replace|change|update|modify).{0,20}(this|the|these).{0,10}with.{0,10}(your|actual)`),
			regexp.MustCompile(`(?i)(see|refer to|check).{0,10}(README|documentation|docs)`),
			regexp.MustCompile("```"),
			regexp.MustCompile("`[^`]+`"),
			regexp.MustCompile(`^\s*#`),
			regexp.MustCompile(`^\s*//`),
		},

		negationPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(never|don't|do not|must not|should not|cannot|can't).{0,50}(leak|steal|expose|send|transmit|exfiltrate)`),
			regexp.MustCompile(`(?i)(avoid|prevent|stop|block|prohibit).{0,50}(leaking|stealing|exposing|exfiltrat)`),
			regexp.MustCompile(`(?i)(ensure|make sure|verify).{0,50}(not|no).{0,30}(leak|expose)`),
		},

		securityToolPatterns: []*regexp.Regexp{
			// Grep/search patterns (security scanners searching for secrets)
			regexp.MustCompile(`(?i)(grep|rg|egrep|fgrep|ag)\s+`),
			regexp.MustCompile(`(?i)(search|find|detect|scan).{0,20}(for|pattern|secret|credential|key|exposure)`),

			// Security scanning context
			regexp.MustCompile(`(?i)(security|threat|vulnerability|attack|malicious)\s+(scan|check|pattern|example|detection)`),
			regexp.MustCompile(`(?i)(prompt|credential|secret|key)\s+(injection|harvesting|leak|pattern)`),

			// Test/validation context
			regexp.MustCompile(`(?i)(test|validate|check|verify)\s+(for|that|if)\s+\w+\s+(secret|credential|key)`),
		},
	}
}

// ShouldExclude returns true if the match should be excluded
func (c *Checker) ShouldExclude(match string, context string) bool {
	// Level 1: Check match itself for placeholder markers
	for _, pattern := range c.placeholderPatterns {
		if pattern.MatchString(match) {
			return true
		}
	}

	// Level 2: Check if it's a variable reference (not hardcoded)
	for _, pattern := range c.variableRefPatterns {
		if pattern.MatchString(context) {
			return true
		}
	}

	// Level 3: Check for documentation context
	for _, pattern := range c.documentationPatterns {
		if pattern.MatchString(context) {
			return true
		}
	}

	// Level 4: Check for negation context (security guidance)
	for _, pattern := range c.negationPatterns {
		if pattern.MatchString(context) {
			return true
		}
	}

	// Level 5: Check for security tool context
	for _, pattern := range c.securityToolPatterns {
		if pattern.MatchString(context) {
			return true
		}
	}

	return false
}

// GetContext extracts surrounding context for a match (±100 chars)
func GetContext(content string, matchStart, matchEnd int) string {
	contextStart := matchStart - 100
	if contextStart < 0 {
		contextStart = 0
	}

	contextEnd := matchEnd + 100
	if contextEnd > len(content) {
		contextEnd = len(content)
	}

	return content[contextStart:contextEnd]
}
