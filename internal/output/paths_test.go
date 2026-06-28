package output

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPathManagerScanID(t *testing.T) {
	pm, err := NewPathManager("*.example.com", "tmp_results")
	if err != nil {
		t.Fatalf("NewPathManager failed: %v", err)
	}

	if !strings.HasPrefix(pm.ScanID, "example-com-") {
		t.Errorf("ScanID = %q; want prefix %q", pm.ScanID, "example-com-")
	}

	if pm.BaseDir != filepath.Join("tmp_results", pm.ScanID) {
		t.Errorf("BaseDir = %q; want %q", pm.BaseDir, filepath.Join("tmp_results", pm.ScanID))
	}
}
