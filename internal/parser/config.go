package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tttturtle-russ/ClawSanitizer/internal/types"
)

func ParseConfig(path string) (*types.OpenClawConfig, error) {
	// Expand ~ to home directory
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("could not determine home directory: %w", err)
		}
		path = filepath.Join(home, path[2:])
	}

	configPath := filepath.Join(path, "openclaw.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("could not read config file %s: %w", configPath, err)
	}

	var cfg types.OpenClawConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("could not parse config file %s: %w", configPath, err)
	}

	return &cfg, nil
}
