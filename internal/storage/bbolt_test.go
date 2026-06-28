package storage

import (
	"path/filepath"
	"testing"
)

func TestBoltDB(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_nullfinder.db")

	db, err := NewBoltDB(dbPath)
	if err != nil {
		t.Fatalf("failed to create BoltDB: %v", err)
	}
	defer db.Close()

	// 1. Test SaveScan and GetScan
	err = db.SaveScan("scan-123", "example.com", "hybrid")
	if err != nil {
		t.Fatalf("failed to save scan: %v", err)
	}

	scan, err := db.GetScan("scan-123")
	if err != nil {
		t.Fatalf("failed to retrieve scan: %v", err)
	}
	if scan.Domain != "example.com" || scan.Mode != "hybrid" {
		t.Errorf("unexpected scan record: %+v", scan)
	}

	// 2. Test SaveAsset and GetAssets
	asset := AssetRecord{
		Domain:        "www.example.com",
		IPs:           []string{"127.0.0.1"},
		Ports:         []int{80, 443},
		IsInteresting: true,
	}

	err = db.SaveAsset("scan-123", asset)
	if err != nil {
		t.Fatalf("failed to save asset: %v", err)
	}

	assets, err := db.GetAssets("scan-123")
	if err != nil {
		t.Fatalf("failed to retrieve assets: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
	if assets[0].Domain != "www.example.com" || !assets[0].IsInteresting {
		t.Errorf("unexpected asset record: %+v", assets[0])
	}
}
