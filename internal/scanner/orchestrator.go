package scanner

import (
	"log"

	"github.com/tttturtle-russ/clawsan/internal/detectors"
	"github.com/tttturtle-russ/clawsan/internal/parser"
	"github.com/tttturtle-russ/clawsan/internal/scoring"
	"github.com/tttturtle-russ/clawsan/internal/types"
)

func Scan(path string) (*types.ScanResult, error) {
	cfg, err := parser.ParseConfig(path)
	if err != nil {
		return nil, err
	}

	workspace, err := parser.ParseWorkspaceFiles(path)
	if err != nil {
		log.Printf("warning: could not parse workspace files: %v", err)
		workspace = nil
	}

	tools, err := parser.ParseMCPTools(path)
	if err != nil {
		log.Printf("warning: could not parse MCP tools: %v", err)
		tools = []parser.MCPTool{}
	}

	slugs := make([]string, len(cfg.Skills))
	for i, s := range cfg.Skills {
		slugs[i] = s.Name
	}
	installedSkills, err := parser.ParseSkillFiles(path, slugs)
	if err != nil {
		log.Printf("warning: could not parse skill files: %v", err)
		installedSkills = nil
	}

	var allFindings []types.Finding

	supplyChain := detectors.NewSupplyChainDetector()
	allFindings = append(allFindings, supplyChain.Detect(cfg)...)
	if len(installedSkills) > 0 {
		allFindings = append(allFindings, supplyChain.CheckSkillMetadata(cfg, installedSkills)...)
	}

	configuration := detectors.NewConfigurationDetector()
	allFindings = append(allFindings, configuration.Detect(cfg)...)

	discovery := detectors.NewDiscoveryDetector()
	allFindings = append(allFindings, discovery.Detect(workspace, tools)...)

	runtime := detectors.NewRuntimeDetector()
	allFindings = append(allFindings, runtime.Detect(workspace, tools, cfg)...)

	if len(installedSkills) > 0 {
		skillContent := detectors.NewSkillContentDetector()
		allFindings = append(allFindings, skillContent.Detect(installedSkills)...)

		skillIdentity := detectors.NewSkillIdentityDetector()
		allFindings = append(allFindings, skillIdentity.Detect(slugs)...)

		composite := detectors.NewSkillCompositeDetector()
		allFindings = append(allFindings, composite.Detect(cfg.Skills, installedSkills)...)
	} else {
		skillIdentity := detectors.NewSkillIdentityDetector()
		allFindings = append(allFindings, skillIdentity.Detect(slugs)...)
	}

	score := scoring.CalculateScore(allFindings)

	return &types.ScanResult{
		Findings:    allFindings,
		Score:       score,
		TotalChecks: 33,
	}, nil
}
