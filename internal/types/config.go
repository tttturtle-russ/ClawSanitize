package types

// OpenClawConfig represents the real openclaw configuration file (~/.openclaw/openclaw.json)
type OpenClawConfig struct {
	Gateway   GatewayConfig   `json:"gateway"`
	Agents    AgentsConfig    `json:"agents"`
	Skills    SkillsConfig    `json:"skills"`
	Logging   LoggingConfig   `json:"logging"`
	Discovery DiscoveryConfig `json:"discovery"`
	Tools     ToolsConfig     `json:"tools"`
	Meta      MetaConfig      `json:"meta"`
}

type GatewayConfig struct {
	Mode                string           `json:"mode"` // "local" | "remote"
	Bind                string           `json:"bind"` // "loopback" | "lan" | "tailnet" | "auto" | "custom"
	Auth                GatewayAuth      `json:"auth"`
	ControlUi           GatewayControlUi `json:"controlUi"`
	Tailscale           GatewayTailscale `json:"tailscale"`
	TrustedProxies      []string         `json:"trustedProxies"`
	AllowRealIpFallback bool             `json:"allowRealIpFallback"`
}

type GatewayAuth struct {
	Mode         string                `json:"mode"` // "none" | "token" | "password" | "trusted-proxy"
	Token        string                `json:"token"`
	Password     string                `json:"password"`
	TrustedProxy *GatewayTrustedProxy  `json:"trustedProxy"`
	RateLimit    *GatewayAuthRateLimit `json:"rateLimit"`
}

type GatewayControlUi struct {
	Enabled                                  bool     `json:"enabled"`
	AllowedOrigins                           []string `json:"allowedOrigins"`
	DangerouslyAllowHostHeaderOriginFallback bool     `json:"dangerouslyAllowHostHeaderOriginFallback"`
	DangerouslyDisableDeviceAuth             bool     `json:"dangerouslyDisableDeviceAuth"`
	AllowInsecureAuth                        bool     `json:"allowInsecureAuth"`
}

type GatewayTailscale struct {
	Mode        string `json:"mode"` // "off" | "serve" | "funnel"
	ResetOnExit bool   `json:"resetOnExit"`
}

type GatewayTrustedProxy struct {
	UserHeader      string   `json:"userHeader"`
	RequiredHeaders []string `json:"requiredHeaders"`
	AllowUsers      []string `json:"allowUsers"`
}

type GatewayAuthRateLimit struct {
	MaxAttempts int `json:"maxAttempts"`
	WindowMs    int `json:"windowMs"`
	LockoutMs   int `json:"lockoutMs"`
}

type AgentsConfig struct {
	Defaults AgentDefaults `json:"defaults"`
}

type AgentDefaults struct {
	Workspace     string         `json:"workspace"`
	MaxConcurrent int            `json:"maxConcurrent"`
	Subagents     SubagentLimits `json:"subagents"`
}

type SubagentLimits struct {
	MaxConcurrent int `json:"maxConcurrent"`
}

type SkillsConfig struct {
	AllowBundled []string                    `json:"allowBundled"`
	Entries      map[string]SkillEntryConfig `json:"entries"`
}

type SkillEntryConfig struct {
	Enabled bool              `json:"enabled"`
	Env     map[string]string `json:"env"`
}

type LoggingConfig struct {
	RedactSensitive string `json:"redactSensitive"` // "off" disables redaction
}

type DiscoveryConfig struct {
	Mdns MdnsConfig `json:"mdns"`
}

type MdnsConfig struct {
	Mode string `json:"mode"` // "off" | "minimal" | "full"
}

type ToolsConfig struct {
	Elevated ElevatedConfig `json:"elevated"`
}

type ElevatedConfig struct {
	Enabled   bool                   `json:"enabled"`
	AllowFrom map[string]interface{} `json:"allowFrom"`
}

type MetaConfig struct {
	LastTouchedVersion string `json:"lastTouchedVersion"`
	LastTouchedAt      string `json:"lastTouchedAt"`
}
