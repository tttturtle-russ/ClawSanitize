package output

import (
	"encoding/json"
	"io"

	"github.com/tttturtle-russ/clawsan/internal/types"
)

func WriteJSON(result *types.ScanResult, w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
