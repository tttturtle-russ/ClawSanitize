package output

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/tttturtle-russ/clawsan/internal/types"
)

// PrintJSON marshals the ScanResult to JSON and writes to stdout
func PrintJSON(result types.ScanResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("failed to encode results as JSON: %w", err)
	}
	return nil
}
