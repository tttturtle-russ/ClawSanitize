package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/tttturtle-russ/ClawSanitizer/internal/parser"
	"github.com/tttturtle-russ/ClawSanitizer/internal/types"
)

type RuntimeDetector struct{}

func NewRuntimeDetector() *RuntimeDetector {
	return &RuntimeDetector{}
}

func (d *RuntimeDetector) Detect(workspace *parser.WorkspaceData, tools []parser.MCPTool, cfg *types.OpenClawConfig) []types.Finding {
	var findings []types.Finding
	findings = append(findings, d.checkR1ForbiddenZoneAccess(workspace, tools)...)
	findings = append(findings, d.checkR2MobileNodePermissionAudit(workspace, tools)...)
	findings = append(findings, d.checkR3BrowserCDPExposure(cfg, tools)...)
	findings = append(findings, d.checkR4WebhookEndpointAuth(cfg)...)
	return findings
}

var runtimeForbiddenPathPatterns = []string{
	"~/.ssh/",
	"/.ssh/",
	".ssh/id_",
	"~/.gnupg/",
	"/.gnupg/",
	"~/.aws/credentials",
	"/.aws/",
	"~/.config/google-chrome",
	"~/library/application support/google/chrome",
	"~/library/keychains/",
	"/library/keychains/",
}

var dotEnvStandaloneRegex = regexp.MustCompile(`(?i)(^|[^a-z0-9_])\.env([^a-z0-9_]|$)`)

func (d *RuntimeDetector) checkR1ForbiddenZoneAccess(workspace *parser.WorkspaceData, tools []parser.MCPTool) []types.Finding {
	var findings []types.Finding

	for _, tool := range tools {
		if matched := matchForbiddenPath(tool.Description); matched != "" {
			findings = append(findings, types.Finding{
				ID:          "RUNTIME-001",
				Severity:    types.SeverityCritical,
				Category:    types.CategoryRuntime,
				Title:       fmt.Sprintf("Tool '%s' references forbidden credential storage", tool.Name),
				Description: fmt.Sprintf("The tool '%s' description references '%s', which is a forbidden sensitive path associated with credentials or secrets.", tool.Name, matched),
				Remediation: "Remove or restrict this tool so it cannot access SSH keys, cloud credentials, browser profiles, keychains, or .env files.",
				FilePath:    tool.Name,
				OWASP:       types.OWASPLLM06,
				CWE:         "CWE-22: Path Traversal",
			})
		}
	}

	if workspace == nil {
		return findings
	}

	workspaceSources := []struct {
		content string
		path    string
	}{
		{content: workspace.AgentsMD, path: workspace.AgentsPath},
		{content: workspace.ToolsMD, path: workspace.ToolsPath},
		{content: workspace.HeartbeatMD, path: workspace.HeartbeatPath},
	}

	for _, source := range workspaceSources {
		if source.content == "" {
			continue
		}
		if matched := matchForbiddenPath(source.content); matched != "" {
			findings = append(findings, types.Finding{
				ID:          "RUNTIME-001",
				Severity:    types.SeverityCritical,
				Category:    types.CategoryRuntime,
				Title:       "Workspace file references forbidden credential storage",
				Description: fmt.Sprintf("Workspace content references '%s', a forbidden sensitive path that can expose credentials or private keys.", matched),
				Remediation: "Remove references that direct agents or tools to access sensitive credential stores and replace with least-privilege data sources.",
				FilePath:    source.path,
				OWASP:       types.OWASPLLM06,
				CWE:         "CWE-22: Path Traversal",
			})
		}
	}

	return findings
}

func matchForbiddenPath(content string) string {
	contentLower := strings.ToLower(content)
	for _, pattern := range runtimeForbiddenPathPatterns {
		if strings.Contains(contentLower, pattern) {
			return pattern
		}
	}
	if dotEnvStandaloneRegex.MatchString(contentLower) {
		return ".env"
	}
	return ""
}

var runtimeMobilePermissionPatterns = []struct {
	permissionType string
	keywords       []string
}{
	{permissionType: "SMS", keywords: []string{"sms", "send_sms", "read_sms"}},
	{permissionType: "contacts", keywords: []string{"contacts", "read_contacts"}},
	{permissionType: "location", keywords: []string{"location", "get_location"}},
	{permissionType: "camera", keywords: []string{"camera", "capture_photo"}},
	{permissionType: "screen_recording", keywords: []string{"screen_recording", "record_screen"}},
}

func (d *RuntimeDetector) checkR2MobileNodePermissionAudit(workspace *parser.WorkspaceData, tools []parser.MCPTool) []types.Finding {
	var findings []types.Finding
	found := map[string]string{}

	for _, tool := range tools {
		descriptionLower := strings.ToLower(tool.Description)
		for _, perm := range runtimeMobilePermissionPatterns {
			if _, exists := found[perm.permissionType]; exists {
				continue
			}
			if containsAny(descriptionLower, perm.keywords) {
				found[perm.permissionType] = tool.Name
			}
		}
	}

	if workspace != nil && workspace.ToolsMD != "" {
		toolsMDLower := strings.ToLower(workspace.ToolsMD)
		for _, perm := range runtimeMobilePermissionPatterns {
			if _, exists := found[perm.permissionType]; exists {
				continue
			}
			if containsAny(toolsMDLower, perm.keywords) {
				filePath := workspace.ToolsPath
				if filePath == "" {
					filePath = "TOOLS.md"
				}
				found[perm.permissionType] = filePath
			}
		}
	}

	for _, perm := range runtimeMobilePermissionPatterns {
		filePath, exists := found[perm.permissionType]
		if !exists {
			continue
		}
		findings = append(findings, types.Finding{
			ID:          "RUNTIME-002",
			Severity:    types.SeverityHigh,
			Category:    types.CategoryRuntime,
			Title:       fmt.Sprintf("Dangerous mobile permission '%s' detected", perm.permissionType),
			Description: fmt.Sprintf("Runtime capability includes '%s', which can access sensitive personal device data at runtime.", perm.permissionType),
			Remediation: "Remove or gate high-risk mobile permissions (SMS, contacts, location, camera, screen recording) behind explicit user approval.",
			FilePath:    filePath,
			OWASP:       types.OWASPLLM06,
			CWE:         "CWE-250: Execution with Unnecessary Privileges",
		})
	}

	return findings
}

var runtimeCDPIndicators = []string{"remote_debugging_port", "--remote-debugging-port", "cdp_port"}

func (d *RuntimeDetector) checkR3BrowserCDPExposure(cfg *types.OpenClawConfig, tools []parser.MCPTool) []types.Finding {
	if cfg == nil {
		return nil
	}

	bindLower := strings.ToLower(cfg.Gateway.Bind)
	for _, indicator := range runtimeCDPIndicators {
		if strings.Contains(bindLower, indicator) {
			return []types.Finding{d.newR3Finding(indicator, "gateway.bind")}
		}
	}
	if strings.Contains(bindLower, "9222") {
		return []types.Finding{d.newR3Finding("9222", "gateway.bind")}
	}

	for _, tool := range tools {
		descriptionLower := strings.ToLower(tool.Description)
		for _, indicator := range runtimeCDPIndicators {
			if strings.Contains(descriptionLower, indicator) {
				return []types.Finding{d.newR3Finding(indicator, tool.Name)}
			}
		}
	}

	return nil
}

func (d *RuntimeDetector) newR3Finding(indicator string, filePath string) types.Finding {
	return types.Finding{
		ID:          "RUNTIME-003",
		Severity:    types.SeverityHigh,
		Category:    types.CategoryRuntime,
		Title:       "Browser CDP debug endpoint may be exposed",
		Description: fmt.Sprintf("Found '%s', which may expose the Chrome DevTools Protocol endpoint and allow remote browser control.", indicator),
		Remediation: "Disable remote debugging in runtime settings and avoid exposing CDP ports on shared or network-accessible interfaces.",
		FilePath:    filePath,
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-284: Improper Access Control",
	}
}

func (d *RuntimeDetector) checkR4WebhookEndpointAuth(cfg *types.OpenClawConfig) []types.Finding {
	if cfg == nil {
		return nil
	}

	bind := strings.TrimSpace(cfg.Gateway.Bind)
	isLoopbackBind := bind == "" || bind == "loopback"
	if isLoopbackBind {
		return nil
	}
	if gatewayHasAuth(cfg) {
		return nil
	}

	return []types.Finding{{
		ID:          "RUNTIME-004",
		Severity:    types.SeverityHigh,
		Category:    types.CategoryRuntime,
		Title:       "Webhook gateway is exposed without authentication",
		Description: fmt.Sprintf("gateway.bind is '%s' (non-loopback) with no authentication configured. Webhook endpoints are reachable by untrusted network clients.", bind),
		Remediation: "Enable gateway authentication (gateway.auth.mode=token) or change gateway.bind to loopback.",
		FilePath:    "gateway.bind",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-306: Missing Authentication for Critical Function",
	}}
}

func containsAny(content string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(content, keyword) {
			return true
		}
	}
	return false
}
