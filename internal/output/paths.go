package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PathManager encapsulates result folder and file management for an individual scan session.
type PathManager struct {
	BaseDir string
	ScanID  string
}

// NewPathManager initializes a new PathManager, deriving a Scan ID from the target and timestamp.
func NewPathManager(target string, baseOutputDir string) (*PathManager, error) {
	if baseOutputDir == "" {
		baseOutputDir = "results"
	}

	// Normalize domain name/input target for the filename/scan-id prefix
	prefix := strings.ToLower(target)
	prefix = strings.TrimPrefix(prefix, "*.")
	prefix = strings.ReplaceAll(prefix, ".", "-")

	// Filter out non-alphanumeric/non-hyphen characters
	var sb strings.Builder
	for _, r := range prefix {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			sb.WriteRune(r)
		}
	}
	prefix = strings.Trim(sb.String(), "-")
	if prefix == "" {
		prefix = "scan"
	}

	// Format matching example: example-com-2026-06-23-120000
	timestamp := time.Now().Format("2006-01-02-150405")
	scanID := fmt.Sprintf("%s-%s", prefix, timestamp)

	return &PathManager{
		BaseDir: filepath.Join(baseOutputDir, scanID),
		ScanID:  scanID,
	}, nil
}

// InitDirectories creates the scan output base directory on disk.
func (pm *PathManager) InitDirectories() error {
	return os.MkdirAll(pm.BaseDir, 0755)
}

// GetFilePath computes the destination path for a given filename.
func (pm *PathManager) GetFilePath(filename string) string {
	return filepath.Join(pm.BaseDir, filename)
}
