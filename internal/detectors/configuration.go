package detectors

import (
	"fmt"
	"strings"

	"github.com/tttturtle-russ/clawsan/internal/types"
)

type ConfigurationDetector struct{}

func NewConfigurationDetector() *ConfigurationDetector {
	return &ConfigurationDetector{}
}

func (d *ConfigurationDetector) Detect(cfg *types.OpenClawConfig) []types.Finding {
	if cfg == nil {
		return nil
	}
	var findings []types.Finding
	if f := d.checkC1DangerouslyDisableDeviceAuth(cfg); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkC2HostHeaderOriginFallback(cfg); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkC3WorkspaceDir(cfg); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkC4GatewayTokenPlaintext(cfg); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkC5GatewayBindLan(cfg); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkC6GatewayNoAuth(cfg); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkC7TailscaleFunnel(cfg); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkC8WildcardAllowedOrigins(cfg); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkC9LoggingRedactOff(cfg); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkC10ElevatedWildcardAllowFrom(cfg); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkC11MdnsFullMode(cfg); f != nil {
		findings = append(findings, *f)
	}
	if f := d.checkC12AllowRealIpFallback(cfg); f != nil {
		findings = append(findings, *f)
	}
	return findings
}

func (d *ConfigurationDetector) checkC1DangerouslyDisableDeviceAuth(cfg *types.OpenClawConfig) *types.Finding {
	if !cfg.Gateway.ControlUi.DangerouslyDisableDeviceAuth {
		return nil
	}
	return &types.Finding{
		ID:          "CONFIG-001",
		Severity:    types.SeverityCritical,
		Category:    types.CategoryConfiguration,
		Title:       "Control UI device authentication is disabled",
		Description: "gateway.controlUi.dangerouslyDisableDeviceAuth is true. Any browser that can reach the gateway can control the agent without device authentication.",
		Remediation: "Remove dangerouslyDisableDeviceAuth from openclaw.json and restart OpenClaw.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-306: Missing Authentication for Critical Function",
	}
}

func (d *ConfigurationDetector) checkC2HostHeaderOriginFallback(cfg *types.OpenClawConfig) *types.Finding {
	if !cfg.Gateway.ControlUi.DangerouslyAllowHostHeaderOriginFallback {
		return nil
	}
	return &types.Finding{
		ID:          "CONFIG-002",
		Severity:    types.SeverityCritical,
		Category:    types.CategoryConfiguration,
		Title:       "Host header origin fallback is enabled (DNS rebinding risk)",
		Description: "gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback is true. This bypasses CORS origin checks using the Host header, enabling DNS rebinding attacks from any website.",
		Remediation: "Remove dangerouslyAllowHostHeaderOriginFallback and set explicit allowedOrigins instead.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-346: Origin Validation Error",
	}
}

func (d *ConfigurationDetector) checkC3WorkspaceDir(cfg *types.OpenClawConfig) *types.Finding {
	dir := cfg.Agents.Defaults.Workspace
	if dir == "" {
		return nil
	}
	dangerous := dir == "/" || dir == "~" || dir == "~/" || dir == "/home" || dir == "/root"
	if !dangerous {
		return nil
	}
	return &types.Finding{
		ID:          "CONFIG-003",
		Severity:    types.SeverityHigh,
		Category:    types.CategoryConfiguration,
		Title:       "Agent workspace is set to an overly broad path",
		Description: fmt.Sprintf("agents.defaults.workspace is '%s'. This gives the AI agent access to a very large portion of the filesystem.", dir),
		Remediation: "Set agents.defaults.workspace to a dedicated directory like '~/.openclaw/workspace'.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-732: Incorrect Permission Assignment for Critical Resource",
	}
}

func (d *ConfigurationDetector) checkC4GatewayTokenPlaintext(cfg *types.OpenClawConfig) *types.Finding {
	token := strings.TrimSpace(cfg.Gateway.Auth.Token)
	if token == "" {
		return nil
	}
	if len(token) < 8 {
		return nil
	}
	return &types.Finding{
		ID:          "CONFIG-004",
		Severity:    types.SeverityHigh,
		Category:    types.CategoryConfiguration,
		Title:       "Gateway auth token is stored as plaintext in config",
		Description: "gateway.auth.token is set as a plaintext string in openclaw.json. Any process that can read this file can steal the token.",
		Remediation: "Use a secrets manager or environment variable for the gateway token instead of hardcoding it in openclaw.json.",
		OWASP:       types.OWASPLLM02,
		CWE:         "CWE-312: Cleartext Storage of Sensitive Information",
	}
}

func (d *ConfigurationDetector) checkC5GatewayBindLan(cfg *types.OpenClawConfig) *types.Finding {
	if cfg.Gateway.Bind != "lan" {
		return nil
	}
	return &types.Finding{
		ID:          "CONFIG-005",
		Severity:    types.SeverityHigh,
		Category:    types.CategoryConfiguration,
		Title:       "OpenClaw gateway is exposed to the local network (bind=lan)",
		Description: "gateway.bind is 'lan', which exposes the gateway to all devices on the local network. Anyone on the same network can connect to the agent.",
		Remediation: "Change gateway.bind to 'loopback' unless you explicitly need LAN access and have authentication configured.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-284: Improper Access Control",
	}
}

func (d *ConfigurationDetector) checkC6GatewayNoAuth(cfg *types.OpenClawConfig) *types.Finding {
	if gatewayHasAuth(cfg) {
		return nil
	}
	return &types.Finding{
		ID:          "CONFIG-006",
		Severity:    types.SeverityCritical,
		Category:    types.CategoryConfiguration,
		Title:       "Gateway has no authentication configured",
		Description: "No gateway.auth token or password is set. Any application that can reach the gateway endpoint can control the AI agent without credentials.",
		Remediation: "Set gateway.auth.mode to 'token' and configure a strong gateway.auth.token in openclaw.json.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-306: Missing Authentication for Critical Function",
	}
}

func (d *ConfigurationDetector) checkC7TailscaleFunnel(cfg *types.OpenClawConfig) *types.Finding {
	if cfg.Gateway.Tailscale.Mode != "funnel" {
		return nil
	}
	return &types.Finding{
		ID:          "CONFIG-007",
		Severity:    types.SeverityCritical,
		Category:    types.CategoryConfiguration,
		Title:       "Tailscale funnel is exposing the gateway to the public internet",
		Description: "gateway.tailscale.mode is 'funnel', which makes the OpenClaw gateway reachable from the public internet via Tailscale Funnel.",
		Remediation: "Change gateway.tailscale.mode to 'serve' (Tailnet only) or 'off'. Enable gateway authentication if remote access is needed.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-284: Improper Access Control",
	}
}

func (d *ConfigurationDetector) checkC8WildcardAllowedOrigins(cfg *types.OpenClawConfig) *types.Finding {
	for _, origin := range cfg.Gateway.ControlUi.AllowedOrigins {
		if strings.TrimSpace(origin) == "*" {
			return &types.Finding{
				ID:          "CONFIG-008",
				Severity:    types.SeverityCritical,
				Category:    types.CategoryConfiguration,
				Title:       "Control UI allows requests from any origin (wildcard CORS)",
				Description: "gateway.controlUi.allowedOrigins contains '*', disabling cross-origin protection. Any website can make authenticated requests to the control UI.",
				Remediation: "Replace '*' in allowedOrigins with the specific origin URLs that should have access.",
				OWASP:       types.OWASPLLM06,
				CWE:         "CWE-346: Origin Validation Error",
			}
		}
	}
	return nil
}

func (d *ConfigurationDetector) checkC9LoggingRedactOff(cfg *types.OpenClawConfig) *types.Finding {
	if cfg.Logging.RedactSensitive != "off" {
		return nil
	}
	return &types.Finding{
		ID:          "CONFIG-009",
		Severity:    types.SeverityMedium,
		Category:    types.CategoryConfiguration,
		Title:       "Sensitive data redaction in logs is disabled",
		Description: "logging.redactSensitive is 'off'. API keys, tokens, and personal data may appear in plain text in log files.",
		Remediation: "Remove the redactSensitive setting or set it to a value other than 'off'.",
		OWASP:       types.OWASPLLM02,
		CWE:         "CWE-532: Insertion of Sensitive Information into Log File",
	}
}

func (d *ConfigurationDetector) checkC10ElevatedWildcardAllowFrom(cfg *types.OpenClawConfig) *types.Finding {
	for key := range cfg.Tools.Elevated.AllowFrom {
		if strings.TrimSpace(key) == "*" {
			return &types.Finding{
				ID:          "CONFIG-010",
				Severity:    types.SeverityCritical,
				Category:    types.CategoryConfiguration,
				Title:       "Elevated tools are allowed from any source (wildcard allowFrom)",
				Description: "tools.elevated.allowFrom contains a wildcard key '*', which grants elevated tool permissions to all requestors.",
				Remediation: "Replace the wildcard in tools.elevated.allowFrom with specific trusted user or channel identifiers.",
				OWASP:       types.OWASPLLM06,
				CWE:         "CWE-250: Execution with Unnecessary Privileges",
			}
		}
	}
	return nil
}

func (d *ConfigurationDetector) checkC11MdnsFullMode(cfg *types.OpenClawConfig) *types.Finding {
	if cfg.Discovery.Mdns.Mode != "full" {
		return nil
	}
	return &types.Finding{
		ID:          "CONFIG-011",
		Severity:    types.SeverityMedium,
		Category:    types.CategoryConfiguration,
		Title:       "mDNS discovery is set to full mode (broadcasts presence on LAN)",
		Description: "discovery.mdns.mode is 'full', which advertises the OpenClaw instance to all devices on the local network via mDNS.",
		Remediation: "Change discovery.mdns.mode to 'minimal' or 'off' to reduce network exposure.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
	}
}

func (d *ConfigurationDetector) checkC12AllowRealIpFallback(cfg *types.OpenClawConfig) *types.Finding {
	if !cfg.Gateway.AllowRealIpFallback {
		return nil
	}
	return &types.Finding{
		ID:          "CONFIG-012",
		Severity:    types.SeverityHigh,
		Category:    types.CategoryConfiguration,
		Title:       "Real IP fallback is enabled (IP spoofing risk)",
		Description: "gateway.allowRealIpFallback is true. This allows clients to inject X-Real-IP or X-Forwarded-For headers to spoof their IP address.",
		Remediation: "Set gateway.allowRealIpFallback to false unless you have a trusted reverse proxy that sets these headers.",
		OWASP:       types.OWASPLLM06,
		CWE:         "CWE-807: Reliance on Untrusted Inputs in a Security Decision",
	}
}

func gatewayHasAuth(cfg *types.OpenClawConfig) bool {
	auth := cfg.Gateway.Auth
	if auth.Mode == "none" {
		return false
	}
	if strings.TrimSpace(auth.Token) != "" {
		return true
	}
	if auth.Mode == "password" && strings.TrimSpace(auth.Password) != "" {
		return true
	}
	if auth.Mode == "trusted-proxy" && auth.TrustedProxy != nil {
		return true
	}
	return false
}
