# ClawSanitizer — OpenClaw Security Vulnerability Scanner

## TL;DR

> **Quick Summary**: Build a Go CLI tool that scans an OpenClaw installation for security vulnerabilities across 4 layers (Supply Chain, Configuration, Discovery, Runtime). Output is non-technical-friendly colored terminal report with severity scoring.
> 
> **Deliverables**:
> - `clawsanitizer` single binary (Go)
> - Detects 23 vulnerability classes mapped to OWASP MCP Top 10
> - Colored terminal output with 🔴🟠🟡 severity indicators
> - JSON output mode for automation (--json flag)
> - README with usage examples
> 
> **Estimated Effort**: Large
> **Parallel Execution**: YES - 5 waves
> **Critical Path**: T1 (scaffolding) → T8 (config parser) → T11 (scanner orchestrator) → T21 (integration test) → F1-F4

---

## Context

### Original Request
User wants to create ClawSanitizer — a tool to detect security vulnerabilities in OpenClaw environments. OpenClaw is a personal AI assistant (246k GitHub stars) that runs on local PCs with MCP-based skills, multi-channel integrations, and mobile nodes. The target audience is **non-technical users** who don't understand AI agent security.

### Interview Summary
**Key Discussions**:
- Existing tools (mcp-scan, Garak, PyRIT, detect-secrets) don't cover OpenClaw end-to-end
- No tool is designed for non-technical users
- OpenClaw has specific attack surface: dmPolicy, HEARTBEAT.md persistence, ClawHub skill supply chain, Gateway network exposure
- User chose **report-only** mode (no auto-fix) for safety

**Research Findings**:
- **OpenClaw architecture**: Gateway (ws://127.0.0.1:18789), config at ~/.openclaw/config.json, workspace files (AGENTS.md, TOOLS.md, HEARTBEAT.md)
- **MCP Tool Poisoning**: 5.5% of public MCP servers contain poisoning payloads; 341 malicious skills found on ClawHub in Feb 2026
- **OWASP MCP Top 10** exists as industry-standard vulnerability taxonomy
- **ClawHub API** available for skill verification (user confirmed)

### Metis Review
**Identified Gaps** (addressed):
- Config file paths → Default ~/.openclaw/ + --path override
- ClawHub integration → API-based (requires network)
- Auto-fix scope → Report-only (no modifications)
- Forbidden zones → All common credential stores defined
- Rug pull detection → All indicators (hash mismatch, maintainer change, timing, git history)

---

## Work Objectives

### Core Objective
Build a standalone Go CLI tool (`clawsanitizer`) that scans an OpenClaw installation for 23 security vulnerabilities across 4 detection layers (Supply Chain: 4 checks, Configuration: 7 checks, Discovery: 6 checks, Runtime: 6 checks), producing a colored terminal report with severity scores that non-technical users can understand and act on.

### Concrete Deliverables
- `clawsanitizer` binary (cross-platform: Linux, macOS, Windows)
- 4 detection modules: Supply Chain, Configuration, Discovery, Runtime
- Terminal output with color-coded findings (fatih/color)
- JSON output mode (--json flag)
- README.md with installation and usage instructions
- Test suite with fixture files (fake OpenClaw configs with known vulnerabilities)

### CLI Interface Contract (CRITICAL - All examples must follow this)

```bash
# Three ways to specify target path:
clawsanitizer scan                          # Uses default ~/.openclaw
clawsanitizer scan /path/to/openclaw       # Positional arg
clawsanitizer scan --path /path/to/openclaw # Flag (overrides positional if both given)

# Flags:
--path PATH    Override target directory (takes precedence over positional arg)
--json         Output as JSON instead of colored terminal

# Precedence: --path flag > positional arg > default (~/.openclaw)
```

### Definition of Done
- [ ] `go build` produces working binary
- [ ] `clawsanitizer scan` detects all 23 vulnerability classes against test fixtures
- [ ] Terminal output has color-coded severity (🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🟢 INFO)
- [ ] `--json` flag outputs valid JSON structure
- [ ] `--path` flag overrides default ~/.openclaw/ location
- [ ] Exit codes: 0=clean, 1=findings, 2=error
- [ ] All tests pass (`go test ./...`)
- [ ] README documents all flags and example usage

### Must Have
- Offline-first design (no network required for config/discovery/runtime layers)
- ClawHub API integration for supply chain layer (graceful offline fallback)
- Plain-language finding descriptions (no jargon)
- Severity scoring: Critical/High/Medium/Low counts → final score 0-100
- Detection rules hard-coded (no config files for MVP)

### Must NOT Have (Guardrails)
- ❌ Plugin/extensibility system
- ❌ Auto-fix functionality
- ❌ Historical scan tracking / database
- ❌ GUI/TUI beyond terminal output
- ❌ Multiple output formats (HTML, PDF, SARIF)
- ❌ Cloud backend / telemetry
- ❌ Multi-language support (English only)
- ❌ Configurable detection rules (hard-coded for MVP)

---

## Verification Strategy (MANDATORY)

> **ZERO HUMAN INTERVENTION** — ALL verification is agent-executed. No exceptions.

### Test Decision
- **Infrastructure exists**: NO (greenfield Go project)
- **Automated tests**: Tests-after (unit tests for each detector, integration test for full scan)
- **Framework**: Go stdlib `testing` package + `testify/assert`
- **Test fixtures**: Create fake OpenClaw configs with known vulnerabilities in `testdata/` directory

### QA Policy
Every task MUST include agent-executed QA scenarios.
Evidence saved to `.sisyphus/evidence/task-{N}-{scenario-slug}.{ext}`.

- **CLI tools**: Use Bash — run commands, check exit codes, parse JSON output with jq
- **Detectors**: Use Bash (go test) — run unit tests, verify specific detector outputs

---

## Execution Strategy

### Parallel Execution Waves

> Maximize throughput by grouping independent tasks into parallel waves.
> Each wave completes before the next begins.
> Target: 5-8 tasks per wave.

```
Wave 1 (Start Immediately — scaffolding + data structures):
├── Task 1: Go project init + CLI framework (cobra) [quick]
├── Task 2: Define data structures (Finding, ScanResult, Config types) [quick]
├── Task 3: Create test fixtures (fake OpenClaw configs) [quick]
├── Task 4: Terminal output formatter (fatih/color) [quick]
└── Task 5: JSON output formatter [quick]

Wave 2 (After Wave 1 — parsers + detectors foundation, MAX PARALLEL):
├── Task 6: OpenClaw config.json parser [unspecified-high]
├── Task 7: Workspace file parser (AGENTS.md, TOOLS.md, HEARTBEAT.md) [unspecified-high]
├── Task 8: MCP tool metadata parser [unspecified-high]
├── Task 9: Supply Chain detector module (ClawHub API client) [unspecified-high]
├── Task 10: Configuration detector module (7 checks: C1-C7) [unspecified-high]
└── Task 11: Discovery detector module (6 checks: D1-D6) [deep]

Wave 3 (After Wave 2 — runtime + orchestration):
├── Task 12: Runtime detector module (6 checks: R1-R6) [deep]
├── Task 13: Scanner orchestrator (run all detectors, aggregate results) [unspecified-high]
├── Task 14: Severity scoring engine [quick]
├── Task 15: Exit code logic (0/1/2) [quick]
└── Task 16: --path flag implementation [quick]

Wave 4 (After Wave 3 — testing + docs):
├── Task 17: Unit tests for Supply Chain detector [unspecified-high]
├── Task 18: Unit tests for Config/Discovery/Runtime detectors [unspecified-high]
├── Task 19: Integration test (full scan against fixtures) [deep]
├── Task 20: README.md with usage examples [writing]
└── Task 21: Build script + cross-compilation (Linux/macOS/Windows) [quick]

Wave FINAL (After ALL tasks — independent review, 4 parallel):
├── Task F1: Plan compliance audit (oracle)
├── Task F2: Code quality review (unspecified-high)
├── Task F3: Real manual QA (unspecified-high)
└── Task F4: Scope fidelity check (deep)

Critical Path: T1 → T6,T7,T8 → T13 → T19 → F1-F4
Parallel Speedup: ~65% faster than sequential
Max Concurrent: 6 (Wave 2)
```

### Dependency Matrix

| Task | Depends On | Blocks | Wave |
|------|------------|--------|------|
| 1 | — | 2-5 | 1 |
| 2 | 1 | 6-14 | 1 |
| 3 | 1 | 17-19 | 1 |
| 4 | 1 | 13 | 1 |
| 5 | 1 | 13 | 1 |
| 6 | 2 | 10, 13 | 2 |
| 7 | 2 | 11, 13 | 2 |
| 8 | 2 | 11, 13 | 2 |
| 9 | 2 | 13, 17 | 2 |
| 10 | 2, 6 | 13, 18 | 2 |
| 11 | 2, 7, 8 | 13, 18 | 2 |
| 12 | 2 | 13, 18 | 3 |
| 13 | 4, 5, 9-12 | 14, 19 | 3 |
| 14 | 13 | 19 | 3 |
| 15 | 13 | 19 | 3 |
| 16 | 1 | 19 | 3 |
| 17 | 3, 9 | F1-F4 | 4 |
| 18 | 3, 10-12 | F1-F4 | 4 |
| 19 | 3, 13-16 | F1-F4 | 4 |
| 20 | 1 | F1-F4 | 4 |
| 21 | 1 | F1-F4 | 4 |
| F1-F4 | 17-21 | — | FINAL |

### Agent Dispatch Summary

- **Wave 1**: 5 tasks — T1-T5 → `quick`
- **Wave 2**: 6 tasks — T6-T8, T9-T10 → `unspecified-high`, T11 → `deep`
- **Wave 3**: 5 tasks — T12 → `deep`, T13 → `unspecified-high`, T14-T16 → `quick`
- **Wave 4**: 5 tasks — T17-T18 → `unspecified-high`, T19 → `deep`, T20 → `writing`, T21 → `quick`
- **Wave FINAL**: 4 tasks — F1 → `oracle`, F2-F3 → `unspecified-high`, F4 → `deep`

---

## TODOs

- [ ] 1. Go project init + CLI framework (cobra)

  **What to do**:
  - Run `go mod init github.com/yourusername/clawsanitizer`
  - Install cobra: `go get -u github.com/spf13/cobra@latest`
  - Create `cmd/root.go` with cobra root command setup
  - Create `cmd/scan.go` with scan subcommand:
    - **Accepts positional arg**: `scan [path]` where path defaults to ~/.openclaw if omitted
    - **Flags**: --path (overrides positional), --json (JSON output)
    - **Precedence**: --path flag > positional arg > default (~/.openclaw)
  - Create `main.go` that calls `cmd.Execute()`
  - Test: `go run main.go scan --help` shows usage

  **Must NOT do**:
  - Don't add other subcommands beyond `scan`
  - Don't add config file support
  - Don't add verbose/debug flags yet (keep simple)

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Straightforward Go scaffolding, standard cobra setup pattern
  - **Skills**: []
    - No specialized skills needed

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 1 (first task, must complete before others)
  - **Blocks**: Tasks 2-5 (all need basic project structure)
  - **Blocked By**: None (can start immediately)

  **References**:
  - External: https://github.com/spf13/cobra#getting-started - Cobra CLI framework setup
  - External: https://gobyexample.com/command-line-flags - Go flag patterns

  **Acceptance Criteria**:
  - [ ] `go mod init` creates go.mod file
  - [ ] cobra dependency in go.mod
  - [ ] `go run main.go scan --help` exits with code 0 and shows usage
  - [ ] `go build` produces binary without errors

  **QA Scenarios**:

  ```
  Scenario: CLI responds to --help
    Tool: Bash
    Preconditions: Go project initialized
    Steps:
      1. Run: go run main.go scan --help
      2. Capture output and exit code
      3. Assert: Exit code = 0
      4. Assert: Output contains "Usage:" and "--path" and "--json"
    Expected Result: Help text displayed, clean exit
    Failure Indicators: Non-zero exit, missing flags in help
    Evidence: .sisyphus/evidence/task-1-help-output.txt

  Scenario: Build succeeds
    Tool: Bash
    Preconditions: All files created
    Steps:
      1. Run: go build -o clawsanitizer
      2. Check exit code
      3. Verify binary exists: ls -l clawsanitizer
    Expected Result: Binary created, no compile errors
    Evidence: .sisyphus/evidence/task-1-build-output.txt
  ```

  **Evidence to Capture**:
  - [ ] task-1-help-output.txt (--help command output)
  - [ ] task-1-build-output.txt (go build success)

  **Commit**: YES
  - Message: `feat(cli): initialize Go project with cobra CLI framework`
  - Files: `go.mod, go.sum, main.go, cmd/root.go, cmd/scan.go`
  - Pre-commit: `go build`

- [ ] 2. Define data structures (Finding, ScanResult, Config types)

  **What to do**:
  - Create `internal/types/finding.go` with Finding struct (ID, Severity, Category, Title, Description, Remediation, FilePath)
  - Create `internal/types/scan_result.go` with ScanResult struct (Findings []Finding, Score int, TotalChecks int, Summary)
  - Create `internal/types/config.go` with OpenClawConfig struct (matches config.json schema)
  - Add Severity constants (CRITICAL, HIGH, MEDIUM, LOW, INFO)
  - Add Category constants (SUPPLY_CHAIN, CONFIGURATION, DISCOVERY, RUNTIME)

  **Must NOT do**:
  - Don't add database/persistence fields
  - Don't add JSON tags for fields not needed in output
  - Keep structs simple (no methods yet beyond constructors)

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Type definitions, no complex logic
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO (depends on T1)
  - **Parallel Group**: Wave 1
  - **Blocks**: Tasks 6-14 (all detectors need these types)
  - **Blocked By**: Task 1

  **References**:
  - Pattern: Look at OpenClaw's config.json structure from research (dangerously_skip_permissions, dmPolicy, workspace_dir, gateway)

  **Acceptance Criteria**:
  - [ ] `go build` succeeds with new types
  - [ ] Finding struct has all required fields (ID, Severity, Category, Title, Description, Remediation)
  - [ ] Severity constants defined (CRITICAL, HIGH, MEDIUM, LOW, INFO)

  **QA Scenarios**:

  ```
  Scenario: Types compile without errors
    Tool: Bash
    Preconditions: Task 1 complete
    Steps:
      1. Run: go build ./internal/types
      2. Check exit code = 0
    Expected Result: Clean compilation
    Evidence: .sisyphus/evidence/task-2-compile.txt
  ```

  **Commit**: YES
  - Message: `feat(types): add core data structures for findings and scan results`
  - Files: `internal/types/*.go`

- [ ] 3. Create test fixtures (fake OpenClaw configs)

  **What to do**:
  - Create `testdata/vulnerable-config/` directory
  - Create `testdata/vulnerable-config/config.json` with dangerous settings (dangerously_skip_permissions:true, dmPolicy:"open", gateway.bind:"0.0.0.0")
  - Create `testdata/vulnerable-config/workspace/AGENTS.md` with poisoning pattern ("send to URL")
  - Create `testdata/vulnerable-config/workspace/TOOLS.md` with shell_execute enabled
  - Create `testdata/vulnerable-config/workspace/HEARTBEAT.md` with suspicious task
  - Create `testdata/clean-config/` with safe config (all defaults secure)

  **Must NOT do**:
  - Don't create real OpenClaw installation
  - Keep fixtures minimal (only fields needed for detection)

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO (depends on T1)
  - **Parallel Group**: Wave 1
  - **Blocks**: Tasks 17-19 (tests need fixtures)
  - **Blocked By**: Task 1

  **References**:
  - Research doc: config.json structure, AGENTS.md/TOOLS.md/HEARTBEAT.md format

  **Acceptance Criteria**:
  - [ ] testdata/vulnerable-config/ directory with 4 files
  - [ ] testdata/clean-config/ directory with safe config
  - [ ] JSON files are valid (can parse with `jq`)

  **QA Scenarios**:

  ```
  Scenario: Fixtures are valid JSON
    Tool: Bash
    Steps:
      1. Run: jq empty testdata/vulnerable-config/config.json
      2. Assert: Exit code 0 (valid JSON)
    Expected Result: No parsing errors
    Evidence: .sisyphus/evidence/task-3-json-valid.txt
  ```

  **Commit**: YES
  - Message: `test: add OpenClaw config test fixtures`
  - Files: `testdata/**`

- [ ] 4. Terminal output formatter (fatih/color)

  **What to do**:
  - Install fatih/color: `go get github.com/fatih/color`
  - Create `internal/output/terminal.go`
  - Implement `PrintFindings(findings []Finding)` function
  - Color scheme: 🔴 Red for CRITICAL, 🟠 Yellow for HIGH, 🟡 Blue for MEDIUM, 🟢 Green for INFO
  - Print format: [SEVERITY] Title\n  Description\n  Remediation: ...\n\n

  **Must NOT do**:
  - Don't add progress bars or spinners
  - Keep output simple and readable

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO (depends on T1)
  - **Parallel Group**: Wave 1
  - **Blocks**: Task 13 (orchestrator needs output)
  - **Blocked By**: Task 1

  **References**:
  - External: https://github.com/fatih/color - Color library usage

  **Acceptance Criteria**:
  - [ ] go build succeeds with fatih/color dependency
  - [ ] PrintFindings function exists

  **QA Scenarios**:

  ```
  Scenario: Colored output works
    Tool: Bash
    Preconditions: Test fixture Finding created
    Steps:
      1. Create small test program that calls PrintFindings with test data
      2. Run and capture output
      3. Check output contains ANSI color codes
    Expected Result: Output has color escape sequences
    Evidence: .sisyphus/evidence/task-4-color-output.txt
  ```

  **Commit**: YES
  - Message: `feat(output): add colored terminal formatter`
  - Files: `internal/output/terminal.go`

- [ ] 5. JSON output formatter

  **What to do**:
  - Create `internal/output/json.go`
  - Implement `PrintJSON(result ScanResult)` function
  - Use encoding/json to marshal ScanResult to stdout
  - Add json tags to types if needed

  **Must NOT do**:
  - Don't add XML or other formats

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO (depends on T1)
  - **Parallel Group**: Wave 1
  - **Blocks**: Task 13
  - **Blocked By**: Task 1

  **References**:
  - Go stdlib: encoding/json package

  **Acceptance Criteria**:
  - [ ] PrintJSON function exists
  - [ ] Output is valid JSON (pipe to jq)

  **QA Scenarios**:

  ```
  Scenario: JSON output is valid
    Tool: Bash
    Steps:
      1. Create test that calls PrintJSON with sample ScanResult
      2. Pipe output to jq
      3. Assert: Exit code 0
    Expected Result: Valid JSON structure
    Evidence: .sisyphus/evidence/task-5-json-valid.txt
  ```

  **Commit**: YES
  - Message: `feat(output): add JSON formatter`
  - Files: `internal/output/json.go`

- [ ] 6. OpenClaw config.json parser

  **What to do**:
  - Create `internal/parser/config.go`
  - Implement `ParseConfig(path string) (*OpenClawConfig, error)`
  - Read ~/.openclaw/config.json (or --path override)
  - Parse JSON into OpenClawConfig struct
  - Handle missing file gracefully (return error)

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with T7, T8, T9, T10, T11)
  - **Blocks**: Task 10, 13
  - **Blocked By**: Task 2

  **References**:
  - Research doc: config.json structure with dangerously_skip_permissions, dmPolicy, gateway fields

  **Acceptance Criteria**:
  - [ ] ParseConfig function parses test fixture
  - [ ] Returns error for missing file

  **QA Scenarios**:

  ```
  Scenario: Parse valid config
    Tool: Bash
    Steps:
      1. go test internal/parser -run TestParseConfig
      2. Assert: Test passes
    Expected Result: Config parsed correctly
    Evidence: .sisyphus/evidence/task-6-parse-test.txt
  ```

  **Commit**: YES
  - Message: `feat(parser): add config.json parser`

- [ ] 7. Workspace file parser (AGENTS.md, TOOLS.md, HEARTBEAT.md)

  **What to do**:
  - Create `internal/parser/workspace.go`
  - Implement `ParseWorkspaceFiles(workspacePath string) (*WorkspaceData, error)`
  - Read AGENTS.md, TOOLS.md, HEARTBEAT.md as plain text
  - Return struct with file contents (we'll pattern match later in detectors)

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2
  - **Blocks**: Task 11, 13
  - **Blocked By**: Task 2

  **References**:
  - Research doc: workspace/ directory structure

  **Acceptance Criteria**:
  - [ ] ParseWorkspaceFiles reads test fixture files
  - [ ] Returns error if directory missing

  **QA Scenarios**:

  ```
  Scenario: Parse workspace files
    Tool: Bash
    Steps:
      1. go test internal/parser -run TestParseWorkspace
      2. Assert: Test passes
    Expected Result: Files read into struct
    Evidence: .sisyphus/evidence/task-7-workspace-test.txt
  ```

  **Commit**: YES
  - Message: `feat(parser): add workspace file parser`

- [ ] 8. MCP tool metadata parser

  **What to do**:
  - Create `internal/parser/mcp.go`
  - Implement `ParseMCPTools(workspacePath string) ([]MCPTool, error)`
  - Look for MCP server definitions in config/workspace
  - Parse tool descriptions and schemas
  - This enables D4 check (tool description poisoning)

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2
  - **Blocks**: Task 11, 13
  - **Blocked By**: Task 2

  **References**:
  - Research: MCP tool format, tool descriptions contain hidden instructions

  **Acceptance Criteria**:
  - [ ] ParseMCPTools extracts tool metadata
  - [ ] Returns empty list if no MCP tools found

  **QA Scenarios**:

  ```
  Scenario: Parse MCP tools
    Tool: Bash
    Steps:
      1. go test internal/parser -run TestParseMCP
      2. Assert: Test passes
    Expected Result: Tool descriptions extracted
    Evidence: .sisyphus/evidence/task-8-mcp-test.txt
  ```

  **Commit**: YES
  - Message: `feat(parser): add MCP tool metadata parser`

- [ ] 9. Supply Chain detector module (ClawHub API client)

  **What to do**:
  - Create `internal/detectors/supply_chain.go`
  - Implement 4 checks (S1-S4):
    - S1: Skill hash verification (compare installed vs ClawHub)
    - S2: ClawHub reputation check (known-bad list API)
    - S3: Unofficial skill sources (GitHub repos <100 stars)
    - S4: Dependency CVE scan (query OSV.dev API)
  - Create `internal/api/clawhub.go` for API client
  - Graceful offline fallback (return warning if API unreachable)

  **Must NOT do**:
  - Don't build skill updater
  - Don't implement rug pull detection yet (complex, save for iteration)

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2
  - **Blocks**: Task 13, 17
  - **Blocked By**: Task 2

  **References**:
  - Research: 341 malicious ClawHub skills found Feb 2026
  - External: OSV.dev API docs for CVE lookup

  **Acceptance Criteria**:
  - [ ] 4 detector functions implemented
  - [ ] API client handles network errors gracefully
  - [ ] Returns findings for test fixtures with known-bad skills

  **QA Scenarios**:

  ```
  Scenario: Detect malicious skill
    Tool: Bash
    Preconditions: Test fixture with malicious skill
    Steps:
      1. go test internal/detectors -run TestSupplyChain
      2. Assert: Finding with ID "SUPPLY_CHAIN-002" detected
    Expected Result: Known-bad skill flagged
    Evidence: .sisyphus/evidence/task-9-supply-chain-test.txt
  ```

  **Commit**: YES
  - Message: `feat(detectors): add supply chain detector with ClawHub integration`

- [ ] 10. Configuration detector module (7 checks: C1-C7)

  **What to do**:
  - Create `internal/detectors/configuration.go`
  - Implement 7 checks:
    - C1: dangerously_skip_permissions: true
    - C2: dmPolicy: "open" + allowFrom: ["*"]
    - C3: workspace_dir: "/" or "~"
    - C4: API keys in config files (regex patterns)
    - C5: Gateway binding to 0.0.0.0
    - C6: Gateway auth disabled
    - C7: Tailscale/SSH tunnel without auth
  - Each check returns Finding with specific ID, severity, remediation

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2
  - **Blocks**: Task 13, 18
  - **Blocked By**: Task 2, Task 6

  **References**:
  - Research: dangerously_skip_permissions is most dangerous setting
  - Research: dmPolicy="open" with allowFrom=["*"] → anyone can control agent

  **Acceptance Criteria**:
  - [ ] 7 detector functions implemented
  - [ ] Test against vulnerable-config fixture returns 7 findings

  **QA Scenarios**:

  ```
  Scenario: Detect all config vulnerabilities
    Tool: Bash
    Steps:
      1. go test internal/detectors -run TestConfiguration
      2. Assert: 7 findings returned (C1-C7)
      3. Check each has CRITICAL or HIGH severity
    Expected Result: All config risks detected
    Evidence: .sisyphus/evidence/task-10-config-test.txt
  ```

  **Commit**: YES
  - Message: `feat(detectors): add configuration detector with 7 checks`

- [ ] 11. Discovery detector module (6 checks: D1-D6)

  **What to do**:
  - Create `internal/detectors/discovery.go`
  - Implement 6 checks:
    - D1: AGENTS.md instruction poisoning (regex for "send to URL", "ignore safety", "read .env")
    - D2: TOOLS.md dangerous capabilities (shell_execute, unsafe_web_browser)
    - D3: HEARTBEAT.md shadow tasks (tasks not in user-created baseline)
    - D4: MCP tool description poisoning (instruction-like strings)
    - D5: Unicode homograph in tool names (lookalike characters)
    - D6: Skill permission overreach (file/shell access beyond stated purpose)
  - Use regex patterns for text matching

  **Must NOT do**:
  - Don't implement ML-based detection
  - Keep regex patterns simple and maintainable

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Pattern detection requires careful regex design and validation against false positives
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2
  - **Blocks**: Task 13, 18
  - **Blocked By**: Task 2, Task 7, Task 8

  **References**:
  - Research: AGENTS.md/TOOLS.md/HEARTBEAT.md are config tampering targets
  - Research: 5.5% of MCP servers contain tool poisoning

  **Acceptance Criteria**:
  - [ ] 6 detector functions implemented
  - [ ] Test fixture with poisoning pattern triggers D1 finding

  **QA Scenarios**:

  ```
  Scenario: Detect instruction poisoning
    Tool: Bash
    Steps:
      1. go test internal/detectors -run TestDiscovery
      2. Assert: Finding with ID "DISCOVERY-001" for AGENTS.md poisoning
      3. Assert: Finding description mentions specific pattern found
    Expected Result: Poisoning patterns detected
    Evidence: .sisyphus/evidence/task-11-discovery-test.txt
  ```

  **Commit**: YES
  - Message: `feat(detectors): add discovery detector with poisoning pattern matching`

- [ ] 12. Runtime detector module (6 checks: R1-R6)

  **What to do**:
  - Create `internal/detectors/runtime.go`
  - Implement 6 checks:
    - R1: Forbidden zone access mapping (which tools can read ~/.ssh/, ~/.gnupg/, ~/.aws/credentials, browser profiles, .env files, Keychain)
    - R2: Android/iOS node permission audit (SMS, contacts, location, camera, screen recording)
    - R3: Browser CDP exposure (Chrome remote debugging port open)
    - R4: Webhook endpoint auth (unauthenticated inbound webhooks)
    - R5: Channel allowlist integrity (overly broad patterns)
    - R6: Session isolation (multiple channels sharing same agent context)
  - Read tool/skill definitions to map permissions

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Permission mapping requires understanding tool capabilities and cross-referencing with forbidden zones
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 3
  - **Blocks**: Task 13, 18
  - **Blocked By**: Task 2

  **References**:
  - Research: Forbidden zones defined (SSH, GPG, AWS, browser, .env, Keychain)
  - Research: Android/iOS node permissions comprehensive list

  **Acceptance Criteria**:
  - [ ] 6 detector functions implemented
  - [ ] Test fixture with tool accessing ~/.ssh/ triggers R1 finding

  **QA Scenarios**:

  ```
  Scenario: Detect forbidden zone access
    Tool: Bash
    Steps:
      1. go test internal/detectors -run TestRuntime
      2. Assert: Finding with ID "RUNTIME-001" for SSH key access
    Expected Result: Permission risks detected
    Evidence: .sisyphus/evidence/task-12-runtime-test.txt
  ```

  **Commit**: YES
  - Message: `feat(detectors): add runtime permission detector`

- [ ] 13. Scanner orchestrator (run all detectors, aggregate results)

  **What to do**:
  - Create `internal/scanner/orchestrator.go`
  - Implement `Scan(path string) (*ScanResult, error)` function
  - Call all 4 detector modules in sequence
  - Aggregate findings into ScanResult
  - Calculate score based on severity counts
  - Implement in cmd/scan.go: read --path and --json flags, call orchestrator, output results

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 3 (sequential after wave 2)
  - **Blocks**: Task 14, 15, 19
  - **Blocked By**: Task 4, 5, 9-12

  **References**:
  - Pattern: Orchestrator pattern (run all detectors, collect results)

  **Acceptance Criteria**:
  - [ ] Scan() function calls all detectors
  - [ ] Returns ScanResult with aggregated findings
  - [ ] cmd/scan.go uses orchestrator

  **QA Scenarios**:

  ```
  Scenario: Full scan end-to-end
    Tool: Bash
    Steps:
      1. go build -o clawsanitizer
      2. ./clawsanitizer scan testdata/vulnerable-config
      3. Assert: Exit code 1 (findings detected)
      4. Check output contains findings from all 4 layers
    Expected Result: Complete scan with findings
    Evidence: .sisyphus/evidence/task-13-full-scan.txt
  ```

  **Commit**: YES
  - Message: `feat(scanner): add orchestrator to run all detectors`

- [ ] 14. Severity scoring engine

  **What to do**:
  - Create `internal/scoring/score.go`
  - Implement `CalculateScore(findings []Finding) int` function
  - Scoring logic: CRITICAL=25pts, HIGH=10pts, MEDIUM=5pts, LOW=1pt deduction from 100
  - Return score 0-100
  - Integrate into orchestrator's ScanResult

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 3
  - **Blocks**: Task 19
  - **Blocked By**: Task 13

  **References**:
  - Simple weighted scoring model

  **Acceptance Criteria**:
  - [ ] CalculateScore function returns 0-100
  - [ ] Test with known findings returns correct score

  **QA Scenarios**:

  ```
  Scenario: Score calculation
    Tool: Bash
    Steps:
      1. go test internal/scoring -run TestCalculateScore
      2. Assert: 1 CRITICAL finding = score 75
      3. Assert: 5 MEDIUM findings = score 75
    Expected Result: Scoring works correctly
    Evidence: .sisyphus/evidence/task-14-scoring-test.txt
  ```

  **Commit**: YES
  - Message: `feat(scoring): add severity scoring engine`

- [ ] 15. Exit code logic (0/1/2)

  **What to do**:
  - In cmd/scan.go, implement exit code logic:
    - 0 = no findings (clean)
    - 1 = findings detected
    - 2 = error (invalid path, parse error)
  - Use os.Exit() appropriately

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 3
  - **Blocks**: Task 19
  - **Blocked By**: Task 13

  **References**:
  - Standard Unix exit code convention

  **Acceptance Criteria**:
  - [ ] Clean config exits with 0
  - [ ] Vulnerable config exits with 1
  - [ ] Invalid path exits with 2

  **QA Scenarios**:

  ```
  Scenario: Exit codes
    Tool: Bash
    Steps:
      1. ./clawsanitizer scan testdata/clean-config; echo $?
      2. Assert: Exit code 0
      3. ./clawsanitizer scan testdata/vulnerable-config; echo $?
      4. Assert: Exit code 1
      5. ./clawsanitizer scan /nonexistent; echo $?
      6. Assert: Exit code 2
    Expected Result: Correct exit codes
    Evidence: .sisyphus/evidence/task-15-exitcodes.txt
  ```

  **Commit**: YES
  - Message: `feat(cli): implement exit code logic`

- [ ] 16. Path handling (positional arg + --path flag)

  **What to do**:
  - In cmd/scan.go, implement path resolution logic:
    1. Accept optional positional arg: `scan [path]`
    2. Accept --path flag
    3. Precedence: --path flag > positional arg > default (~/.openclaw)
  - Validate resolved path exists before scanning
  - Return error with clear message if path doesn't exist

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 3
  - **Blocks**: Task 19
  - **Blocked By**: Task 1

  **References**:
  - Cobra positional args handling: https://github.com/spf13/cobra#positional-and-custom-arguments
  - Cobra flag handling

  **Acceptance Criteria**:
  - [ ] Default path (~/.openclaw) used when no args given
  - [ ] Positional arg overrides default
  - [ ] --path flag overrides both positional and default
  - [ ] Invalid path returns exit code 2 with error message

  **QA Scenarios**:

  ```
  Scenario: Default path
    Tool: Bash
    Steps:
      1. ./clawsanitizer scan
      2. Check output mentions ~/.openclaw
    Expected Result: Uses default path
    Evidence: .sisyphus/evidence/task-16-default-path.txt

  Scenario: Positional arg
    Tool: Bash
    Steps:
      1. ./clawsanitizer scan testdata/clean-config
      2. Check output mentions testdata/clean-config
    Expected Result: Uses positional arg path
    Evidence: .sisyphus/evidence/task-16-positional.txt

  Scenario: Flag override
    Tool: Bash
    Steps:
      1. ./clawsanitizer scan testdata/clean-config --path testdata/vulnerable-config
      2. Check output scans vulnerable-config (not clean-config)
    Expected Result: --path flag takes precedence
    Evidence: .sisyphus/evidence/task-16-flag-override.txt

  Scenario: Invalid path error
    Tool: Bash
    Steps:
      1. ./clawsanitizer scan /nonexistent/path 2>&1; echo $?
      2. Assert: Exit code = 2
      3. Assert: Error message contains "/nonexistent/path"
    Expected Result: Clean error, exit code 2
    Evidence: .sisyphus/evidence/task-16-invalid-path.txt
  ```
    Evidence: .sisyphus/evidence/task-16-path-flag.txt
  ```

  **Commit**: YES
  - Message: `feat(cli): add --path flag for custom OpenClaw location`

- [ ] 17. Unit tests for Supply Chain detector

  **What to do**:
  - Create `internal/detectors/supply_chain_test.go`
  - Test each S1-S4 check individually
  - Mock ClawHub API responses (use httptest)
  - Test offline fallback behavior

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4
  - **Blocks**: F1-F4
  - **Blocked By**: Task 3, Task 9

  **References**:
  - Go stdlib: testing package, httptest for API mocking

  **Acceptance Criteria**:
  - [ ] go test internal/detectors -run TestSupplyChain passes
  - [ ] All S1-S4 checks covered

  **QA Scenarios**:

  ```
  Scenario: Unit tests pass
    Tool: Bash
    Steps:
      1. go test internal/detectors -v -run TestSupplyChain
      2. Assert: All tests PASS
    Expected Result: Test coverage for supply chain
    Evidence: .sisyphus/evidence/task-17-test-output.txt
  ```

  **Commit**: YES
  - Message: `test: add unit tests for supply chain detector`

- [ ] 18. Unit tests for Config/Discovery/Runtime detectors

  **What to do**:
  - Create test files: configuration_test.go, discovery_test.go, runtime_test.go
  - Test each detector function with test fixtures
  - Verify findings have correct IDs, severities, descriptions

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4
  - **Blocks**: F1-F4
  - **Blocked By**: Task 3, Task 10-12

  **References**:
  - testdata/ fixtures for test data

  **Acceptance Criteria**:
  - [ ] All detector tests pass
  - [ ] Coverage >80% for detector packages

  **QA Scenarios**:

  ```
  Scenario: All detector tests pass
    Tool: Bash
    Steps:
      1. go test internal/detectors/... -v
      2. Assert: PASS for all tests
    Expected Result: Complete detector test coverage
    Evidence: .sisyphus/evidence/task-18-all-tests.txt
  ```

  **Commit**: YES
  - Message: `test: add unit tests for all detector modules`

- [ ] 19. Integration test (full scan against fixtures)

  **What to do**:
  - Create `cmd/scan_test.go`
  - Test full scan workflow against testdata/vulnerable-config
  - Verify: correct number of findings, correct exit code, JSON output valid
  - Test against testdata/clean-config → no findings

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Integration test requires orchestrating full scan flow and validating all layers work together
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 4
  - **Blocks**: F1-F4
  - **Blocked By**: Task 3, Task 13-16

  **References**:
  - Integration test pattern: run binary as subprocess, capture output

  **Acceptance Criteria**:
  - [ ] Integration test passes
  - [ ] Detects all expected findings in vulnerable-config
  - [ ] Returns no findings for clean-config

  **QA Scenarios**:

  ```
  Scenario: Full integration test
    Tool: Bash
    Steps:
      1. go test cmd/... -v
      2. Assert: Integration test PASS
      3. Verify: vulnerable-config produces findings
      4. Verify: clean-config produces no findings
    Expected Result: End-to-end scan works correctly
    Evidence: .sisyphus/evidence/task-19-integration.txt
  ```

  **Commit**: YES
  - Message: `test: add integration test for full scan workflow`

- [ ] 20. README.md with usage examples

  **What to do**:
  - Create README.md
  - Sections: Overview, Installation, Usage, Examples, Detectors, Contributing
  - Include example commands: `clawsanitizer scan`, `--path`, `--json`
  - Document all 23 detector checks (S1-S4, C1-C7, D1-D6, R1-R6)
  - Explain severity levels and scoring
  - Add troubleshooting section

  **Must NOT do**:
  - Don't write excessive marketing copy
  - Keep technical but accessible

  **Recommended Agent Profile**:
  - **Category**: `writing`
    - Reason: Documentation-focused task
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4
  - **Blocks**: F1-F4
  - **Blocked By**: Task 1

  **References**:
  - Research doc: list of all detector checks

  **Acceptance Criteria**:
  - [ ] README.md exists with all sections
  - [ ] All 23 detectors documented
  - [ ] Usage examples provided

  **QA Scenarios**:

  ```
  Scenario: README is complete
    Tool: Bash
    Steps:
      1. Check README.md exists
      2. grep "Usage" README.md
      3. grep "Installation" README.md
      4. Count detector documentation (should be 23)
    Expected Result: Complete documentation
    Evidence: .sisyphus/evidence/task-20-readme-check.txt
  ```

  **Commit**: YES
  - Message: `docs: add comprehensive README with usage examples`

- [ ] 21. Build script + cross-compilation (Linux/macOS/Windows)

  **What to do**:
  - Create `build.sh` script
  - Use `GOOS` and `GOARCH` for cross-compilation
  - Build for: linux/amd64, darwin/amd64, darwin/arm64, windows/amd64
  - Output binaries to `dist/` directory
  - Create `release.sh` for versioned releases

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4
  - **Blocks**: F1-F4
  - **Blocked By**: Task 1

  **References**:
  - Go cross-compilation docs

  **Acceptance Criteria**:
  - [ ] build.sh creates binaries for all platforms
  - [ ] Binaries execute correctly

  **QA Scenarios**:

  ```
  Scenario: Cross-compilation works
    Tool: Bash
    Steps:
      1. bash build.sh
      2. ls dist/
      3. Assert: 4+ binaries exist (linux, darwin x2, windows)
      4. file dist/clawsanitizer-linux-amd64
      5. Assert: Output contains "ELF 64-bit"
    Expected Result: Binaries for all platforms
    Evidence: .sisyphus/evidence/task-21-build.txt
  ```

  **Commit**: YES
  - Message: `build: add cross-compilation script for all platforms`

---

## Final Verification Wave (MANDATORY — after ALL implementation tasks)

> 4 review agents run in PARALLEL. ALL must APPROVE. Rejection → fix → re-run.

- [ ] F1. **Plan Compliance Audit** — `oracle`
  Read the plan end-to-end. For each "Must Have": verify implementation exists (grep code, run binary with test inputs). For each "Must NOT Have": search codebase for forbidden patterns (plugin system, auto-fix, GUI code) — reject with file:line if found. Check evidence files exist in .sisyphus/evidence/. Compare deliverables against plan.
  Output: `Must Have [N/N] | Must NOT Have [N/N] | Tasks [N/N] | VERDICT: APPROVE/REJECT`

- [ ] F2. **Code Quality Review** — `unspecified-high`
  Run `go build`, `go vet ./...`, `go test ./...`. Review all .go files for: empty error handling (`if err != nil { return err }` without context), TODO comments without GitHub issues, magic numbers (hardcoded strings/numbers), inconsistent naming. Check AI slop: excessive comments explaining obvious code, over-abstraction (interfaces with single impl), generic names (data/result/item/temp).
  Output: `Build [PASS/FAIL] | Vet [PASS/FAIL] | Tests [N pass/N fail] | Files [N clean/N issues] | VERDICT`

- [ ] F3. **Real Manual QA** — `unspecified-high`
  Build binary (`go build -o clawsanitizer`). Test against EVERY test fixture in testdata/ — verify findings match expected. Test --json output (pipe to jq, validate schema). Test --path override with non-default location. Test with missing OpenClaw install (should error gracefully). Test exit codes: clean config (0), config with findings (1), invalid path (2). Save terminal output screenshots to `.sisyphus/evidence/final-qa/`.
  Output: `Fixtures [N/N pass] | Flags [N/N work] | Exit Codes [N/N correct] | VERDICT`

- [ ] F4. **Scope Fidelity Check** — `deep`
  For each task: read "What to do", git diff the actual changes. Verify 1:1 — everything in spec was built (no missing detectors), nothing beyond spec was built (no plugin system, no auto-fix code). Check "Must NOT do" compliance from plan. Detect cross-task contamination: Task N modifying files it shouldn't touch. Flag unaccounted code additions.
  Output: `Tasks [N/N compliant] | Contamination [CLEAN/N issues] | Unaccounted [CLEAN/N files] | VERDICT`

---

## Commit Strategy

- **Per-task commits**: Each completed task gets one commit
- **Format**: `type(scope): description` (e.g., `feat(scanner): add config detector module`)
- **Pre-commit**: `go test ./... && go vet ./...`
- **Final commit**: `chore: release v0.1.0` (after all F1-F4 pass)

---

## Success Criteria

### Verification Commands
```bash
# Build
go build -o clawsanitizer
# Expected: Binary created successfully

# Run against test fixture
./clawsanitizer scan testdata/vulnerable-config
# Expected: Colored output with findings, exit code 1

# JSON output
./clawsanitizer scan testdata/vulnerable-config --json | jq '.findings | length'
# Expected: Number > 0

# Clean config
./clawsanitizer scan testdata/clean-config
# Expected: "No vulnerabilities found", exit code 0

# All tests
go test ./... -v
# Expected: All tests pass
```

### Final Checklist
- [ ] All "Must Have" present (23 detector checks, colored output, JSON mode, --path flag)
- [ ] All "Must NOT Have" absent (no plugins, no auto-fix, no GUI, no config files)
- [ ] All tests pass (`go test ./...`)
- [ ] Binary builds for Linux/macOS/Windows
- [ ] README documents all usage patterns
- [ ] Evidence files for all tasks in .sisyphus/evidence/
