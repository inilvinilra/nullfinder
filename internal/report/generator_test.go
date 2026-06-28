package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nullfinder/internal/storage"
)

func TestReportCompilation(t *testing.T) {
	tmpDir := t.TempDir()

	assets := []storage.AssetRecord{
		{
			Domain:            "www.example.com",
			IPs:               []string{"127.0.0.1"},
			Ports:             []int{80, 443},
			IsInteresting:     true,
			InterestingReason: "Title contains admin",
		},
	}

	// 1. JSON
	jsonPath := filepath.Join(tmpDir, "report.json")
	if err := ExportJSON(jsonPath, assets); err != nil {
		t.Fatalf("failed to compile JSON report: %v", err)
	}

	// 2. YAML
	yamlPath := filepath.Join(tmpDir, "report.yaml")
	if err := ExportYAML(yamlPath, assets); err != nil {
		t.Fatalf("failed to compile YAML report: %v", err)
	}

	// 3. CSV
	csvPath := filepath.Join(tmpDir, "report.csv")
	if err := ExportCSV(csvPath, assets); err != nil {
		t.Fatalf("failed to compile CSV report: %v", err)
	}

	// 4. TXT
	txtPath := filepath.Join(tmpDir, "report.txt")
	if err := ExportTXT(txtPath, "example.com", "scan-123", assets); err != nil {
		t.Fatalf("failed to compile TXT report: %v", err)
	}

	// 5. HTML
	htmlPath := filepath.Join(tmpDir, "report.html")
	if err := ExportHTML(htmlPath, "example.com", "scan-123", assets); err != nil {
		t.Fatalf("failed to compile HTML report: %v", err)
	}

	// Verify all exist
	for _, fp := range []string{jsonPath, yamlPath, csvPath, txtPath, htmlPath} {
		if _, err := os.Stat(fp); os.IsNotExist(err) {
			t.Errorf("expected report file to be created: %s", fp)
		}
	}

	txtData, err := os.ReadFile(txtPath)
	if err != nil {
		t.Fatalf("failed to read txt report: %v", err)
	}
	if !strings.Contains(string(txtData), "Evidence Score:") {
		t.Fatalf("expected txt report to include evidence score, got:\n%s", string(txtData))
	}
}
