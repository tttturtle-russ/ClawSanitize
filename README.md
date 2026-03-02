# ClawSanitizer

[![Go Version](https://img.shields.io/github/go-mod/go-version/yourusername/clawsanitizer)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

The security scanner for OpenClaw.

## Overview

ClawSanitizer helps you secure your OpenClaw installation. It scans your configuration, installed skills, and workspace files to identify potential security risks like malicious skills, dangerous permissions, or exposed credentials. This tool is designed for personal AI assistant users and maps findings to the OWASP Top 10 for LLM Applications.

## Installation

### Using Go

If you have Go installed, you can install the latest version directly:

```bash
go install github.com/yourusername/clawsanitizer@latest
```

### From Source

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/clawsanitizer.git
   ```
2. Build the binary:
   ```bash
   cd clawsanitizer
   go build -o clawsanitizer
   ```

## Quick Start

Run a default scan of your OpenClaw installation:
```bash
clawsanitizer scan
```

Scan a specific OpenClaw directory:
```bash
clawsanitizer scan ~/.openclaw/custom-path
```

Generate a JSON report for automated analysis:
```bash
clawsanitizer scan --json
```

## Usage

```text
Usage:
  clawsanitizer scan [path] [flags]

Flags:
  -h, --help          help for scan
      --json          output results as JSON
      --path string   path to OpenClaw installation
```

## What It Detects

ClawSanitizer performs 23 security checks across four categories.

### Supply Chain (S1-S4)

| ID | Severity | Detects |
|----|----------|---------|
| SUPPLY_CHAIN-001 | HIGH | Skill has no integrity hash (unverifiable code) |
| SUPPLY_CHAIN-002 | CRITICAL | Skill is flagged as malicious on ClawHub |
| SUPPLY_CHAIN-003 | MEDIUM | Skill is from an unofficial source |
| SUPPLY_CHAIN-004 | HIGH | Skill has a high-risk name from an unverified source |

### Configuration (C1-C7)

| ID | Severity | Detects |
|----|----------|---------|
| CONFIG-001 | CRITICAL | All permission prompts are disabled |
| CONFIG-002 | HIGH | Anyone can send commands via direct messages (open DM policy) |
| CONFIG-003 | HIGH | Workspace directory is set to an overly broad path (e.g., / or ~) |
| CONFIG-004 | HIGH | API key is stored in plaintext in config file |
| CONFIG-005 | HIGH | Gateway is exposed to all network interfaces (0.0.0.0) |
| CONFIG-006 | MEDIUM | Gateway authentication is disabled |
| CONFIG-007 | HIGH | Tailscale or SSH tunnel enabled without authentication |

### Discovery (D1-D6)

| ID | Severity | Detects |
|----|----------|---------|
| DISCOVERY-001 | CRITICAL | Suspicious data exfiltration or safety bypass instructions in AGENTS.md |
| DISCOVERY-002 | HIGH | Dangerous tool capabilities (like shell access) found in TOOLS.md |
| DISCOVERY-003 | CRITICAL | Suspicious background or scheduled tasks found in HEARTBEAT.md |
| DISCOVERY-004 | CRITICAL | Hidden malicious instructions in MCP tool descriptions |
| DISCOVERY-005 | HIGH | Tool names using look-alike Unicode characters (homograph attack) |
| DISCOVERY-006 | HIGH | Tool references sensitive paths like SSH keys or browser profiles |

### Runtime (R1-R6)

| ID | Severity | Detects |
|----|----------|---------|
| RUNTIME-001 | CRITICAL | Workspace or tool references forbidden credential storage (SSH, AWS, etc.) |
| RUNTIME-002 | HIGH | Dangerous mobile permissions (SMS, camera, location) detected in tools |
| RUNTIME-003 | HIGH | Browser CDP debug endpoint exposure |
| RUNTIME-004 | HIGH | Webhook gateway exposed without authentication on non-local interface |
| RUNTIME-005 | MEDIUM | Wildcard channel patterns in the allowlist |
| RUNTIME-006 | MEDIUM | Open DM policy spanning too many channels |

## Severity Scoring

ClawSanitizer calculates a security score starting from 100. Each finding reduces the score based on its severity:

- **CRITICAL**: 25 points
- **HIGH**: 10 points
- **MEDIUM**: 5 points
- **LOW**: 1 point

A higher score indicates a more secure installation.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean (no findings) |
| 1 | Findings detected |
| 2 | Error (e.g., path not found, scan failed) |

## Supported Platforms

- Linux
- macOS (Intel + Apple Silicon)
- Windows

## Troubleshooting

### "OpenClaw not found"
The scanner looks for OpenClaw in `~/.openclaw/` by default. If your installation is elsewhere, use the `--path` flag:
`clawsanitizer scan --path /your/custom/path`

### "Permission denied"
Ensure you have read access to the OpenClaw configuration directory and the workspace files within it. On macOS or Linux, you might need to check folder permissions.

### "No findings (is path correct?)"
If you see no findings but expect some, verify that the path you are scanning actually contains a `config.json` and a `workspace` folder.
