package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/tttturtle-russ/clawsan/internal/parser"
	"github.com/tttturtle-russ/clawsan/internal/types"
)

type LOTSCategory struct {
	Category    string
	Risk        string
	Description string
}

type SuspiciousURLDetector struct {
	suspiciousDomains map[string]LOTSCategory
	legitimateAPIs    map[string]bool
}

func NewSuspiciousURLDetector() *SuspiciousURLDetector {
	return &SuspiciousURLDetector{
		suspiciousDomains: map[string]LOTSCategory{
			// Paste Services (LOTS: Exfiltration, C&C)
			"pastebin.com":   {Category: "paste", Risk: "exfiltration", Description: "paste service commonly used for data exfiltration"},
			"hastebin.com":   {Category: "paste", Risk: "exfiltration", Description: "ephemeral paste service"},
			"paste.ee":       {Category: "paste", Risk: "exfiltration", Description: "paste service with no registration"},
			"rentry.co":      {Category: "paste", Risk: "exfiltration", Description: "markdown paste service"},
			"privatebin.net": {Category: "paste", Risk: "exfiltration", Description: "encrypted paste service"},
			"dpaste.com":     {Category: "paste", Risk: "exfiltration", Description: "Django-powered pastebin"},
			"ghostbin.com":   {Category: "paste", Risk: "exfiltration", Description: "anonymous paste service"},

			// File Sharing (LOTS: Download, Exfiltration)
			"transfer.sh":   {Category: "file_sharing", Risk: "exfiltration", Description: "anonymous file upload"},
			"filebin.net":   {Category: "file_sharing", Risk: "exfiltration", Description: "temporary file storage"},
			"gofile.io":     {Category: "file_sharing", Risk: "exfiltration", Description: "free file sharing"},
			"anonfiles.com": {Category: "file_sharing", Risk: "malware", Description: "anonymous file hosting (malware distribution)"},
			"mega.nz":       {Category: "file_sharing", Risk: "download", Description: "cloud storage (command downloads)"},
			"catbox.moe":    {Category: "file_sharing", Risk: "exfiltration", Description: "anonymous file hosting"},
			"file.io":       {Category: "file_sharing", Risk: "exfiltration", Description: "ephemeral file sharing"},
			"ufile.io":      {Category: "file_sharing", Risk: "exfiltration", Description: "temporary file hosting"},

			// Webhook/Request Inspection (LOTS: C&C, Exfiltration)
			"webhook.site":       {Category: "webhook", Risk: "exfiltration", Description: "webhook inspector captures all requests"},
			"requestbin.com":     {Category: "webhook", Risk: "exfiltration", Description: "HTTP request inspector"},
			"hookbin.com":        {Category: "webhook", Risk: "exfiltration", Description: "webhook testing service"},
			"pipedream.net":      {Category: "webhook", Risk: "exfiltration", Description: "workflow automation with data capture"},
			"beeceptor.com":      {Category: "webhook", Risk: "exfiltration", Description: "HTTP mocking/inspection"},
			"requestcatcher.com": {Category: "webhook", Risk: "exfiltration", Description: "request debugging service"},
			"postb.in":           {Category: "webhook", Risk: "exfiltration", Description: "HTTP request bin"},

			// Tunneling/Proxy (LOTS: C&C, Bypass)
			"ngrok.io":       {Category: "tunnel", Risk: "c2", Description: "tunnel service for C&C"},
			"localtunnel.me": {Category: "tunnel", Risk: "c2", Description: "expose localhost to internet"},
			"serveo.net":     {Category: "tunnel", Risk: "c2", Description: "SSH tunnel service"},
			"localhost.run":  {Category: "tunnel", Risk: "c2", Description: "instant tunnels to localhost"},
			"tunnelmole.com": {Category: "tunnel", Risk: "c2", Description: "secure tunneling service"},
			"telebit.cloud":  {Category: "tunnel", Risk: "c2", Description: "reverse proxy for localhost"},
			"expose.dev":     {Category: "tunnel", Risk: "c2", Description: "tunneling for local development"},

			// Code Execution (LOTS: C&C, Download)
			"replit.com":     {Category: "code_execution", Risk: "c2", Description: "online code execution environment"},
			"glitch.com":     {Category: "code_execution", Risk: "c2", Description: "hosted app environment"},
			"repl.co":        {Category: "code_execution", Risk: "c2", Description: "Replit short domain"},
			"glitch.me":      {Category: "code_execution", Risk: "c2", Description: "Glitch app subdomain"},
			"codepen.io":     {Category: "code_execution", Risk: "download", Description: "frontend code hosting"},
			"codesandbox.io": {Category: "code_execution", Risk: "download", Description: "online IDE"},
			"jsfiddle.net":   {Category: "code_execution", Risk: "download", Description: "JavaScript playground"},

			// URL Shorteners (LOTS: Obfuscation)
			"bit.ly":      {Category: "shortener", Risk: "obfuscation", Description: "URL shortener (hides destination)"},
			"tinyurl.com": {Category: "shortener", Risk: "obfuscation", Description: "URL shortener"},
			"t.co":        {Category: "shortener", Risk: "obfuscation", Description: "Twitter URL shortener"},
			"goo.gl":      {Category: "shortener", Risk: "obfuscation", Description: "Google URL shortener (deprecated)"},
			"is.gd":       {Category: "shortener", Risk: "obfuscation", Description: "URL shortening service"},
			"ow.ly":       {Category: "shortener", Risk: "obfuscation", Description: "Hootsuite URL shortener"},
			"short.io":    {Category: "shortener", Risk: "obfuscation", Description: "branded link shortener"},
			"rebrand.ly":  {Category: "shortener", Risk: "obfuscation", Description: "URL shortener"},
			"cutt.ly":     {Category: "shortener", Risk: "obfuscation", Description: "URL shortener"},
			"v.gd":        {Category: "shortener", Risk: "obfuscation", Description: "short URL service"},
			"rb.gy":       {Category: "shortener", Risk: "obfuscation", Description: "Rebrandly short domain"},

			// Testing/Security Tools (legitimate but abused)
			"burpcollaborator.net": {Category: "testing", Risk: "exfiltration", Description: "Burp Suite interaction testing"},
			"interact.sh":          {Category: "testing", Risk: "exfiltration", Description: "interaction testing service"},
			"canarytokens.com":     {Category: "testing", Risk: "exfiltration", Description: "honeytokens for detection"},

			// Cloud Storage (legitimate but abused)
			"dropbox.com":      {Category: "file_sharing", Risk: "exfiltration", Description: "cloud storage (check context)"},
			"drive.google.com": {Category: "file_sharing", Risk: "exfiltration", Description: "Google Drive (check context)"},
		},

		legitimateAPIs: map[string]bool{
			// AI Providers (official API endpoints only)
			"api.anthropic.com": true,
			"api.openai.com":    true,
			"api.together.xyz":  true,
			"api.cohere.ai":     true,

			// Package Registries (read-only)
			"registry.npmjs.org": true,
			"pypi.org":           true,
			"crates.io":          true,
			"rubygems.org":       true,

			// Version Control (API endpoints only)
			"api.github.com": true,
			"api.gitlab.com": true,

			// Communication (API only, NOT webhooks)
			"api.slack.com":    true,
			"api.telegram.org": true,
		},
	}
}

var urlPattern = regexp.MustCompile(`https?://([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})(?:[^\s]*)?`)

func (d *SuspiciousURLDetector) Detect(workspace *parser.WorkspaceData, skills []parser.InstalledSkill) []types.Finding {
	var findings []types.Finding

	// Check workspace files
	if workspace != nil {
		files := map[string]string{
			workspace.SoulPath:     workspace.SoulMD,
			workspace.MemoryPath:   workspace.MemoryMD,
			workspace.IdentityPath: workspace.IdentityMD,
			workspace.AgentsPath:   workspace.AgentsMD,
		}

		for path, content := range files {
			if content != "" {
				findings = append(findings, d.scanContent(path, content)...)
			}
		}
	}

	// Check skill SKILL.md files
	for _, skill := range skills {
		if skill.SkillMD != nil {
			findings = append(findings, d.scanContent(skill.SkillMD.Path, skill.SkillMD.Content)...)
		}
	}

	// Check skill code files
	for _, skill := range skills {
		for _, codeFile := range skill.CodeFiles {
			findings = append(findings, d.scanContent(codeFile.Path, codeFile.Content)...)
		}
	}

	return findings
}

func (d *SuspiciousURLDetector) scanContent(filePath, content string) []types.Finding {
	var findings []types.Finding
	seenDomains := make(map[string]bool)

	matches := urlPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		fullURL := match[0]
		domain := strings.ToLower(match[1])

		suspiciousDomain := ""
		var lotsInfo LOTSCategory
		var found bool

		if info, exists := d.suspiciousDomains[domain]; exists {
			suspiciousDomain = domain
			lotsInfo = info
			found = true
		}

		if !found {
			parts := strings.Split(domain, ".")
			if len(parts) >= 2 {
				baseDomain := parts[len(parts)-2] + "." + parts[len(parts)-1]
				if info, exists := d.suspiciousDomains[baseDomain]; exists {
					suspiciousDomain = baseDomain
					lotsInfo = info
					found = true
				}
			}

			if !found && len(parts) >= 3 {
				baseDomain := parts[len(parts)-3] + "." + parts[len(parts)-2] + "." + parts[len(parts)-1]
				if info, exists := d.suspiciousDomains[baseDomain]; exists {
					suspiciousDomain = baseDomain
					lotsInfo = info
					found = true
				}
			}
		}

		if !found {
			continue
		}

		// Skip if already reported for this file
		if seenDomains[suspiciousDomain] {
			continue
		}

		// Skip if legitimate API
		if isLegit, exists := d.legitimateAPIs[domain]; exists && isLegit {
			continue
		}

		severity := types.SeverityHigh
		if lotsInfo.Risk == "malware" {
			severity = types.SeverityCritical
		}

		findings = append(findings, types.Finding{
			ID:       "SUSPICIOUS_URL-001",
			Severity: severity,
			Category: types.CategorySuspiciousURL,
			Title:    "Suspicious domain detected: " + suspiciousDomain,
			Description: fmt.Sprintf("The file references %s, a %s (LOTS category: %s). This service is commonly abused for %s.",
				suspiciousDomain, lotsInfo.Description, lotsInfo.Category, lotsInfo.Risk),
			Remediation: "Verify this URL is intentional and required. If not needed, remove it. If needed, document why in comments.",
			FilePath:    filePath,
			Snippet:     fullURL,
			OWASP:       types.OWASPLLM03,
			CWE:         "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
			References:  []string{"https://lots-project.com/"},
		})

		seenDomains[suspiciousDomain] = true
	}

	return findings
}
