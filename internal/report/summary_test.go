package report

import (
	"testing"

	"nullfinder/internal/storage"
)

func TestBuildSummary(t *testing.T) {
	assets := []storage.AssetRecord{
		{
			Domain:        "www.example.com",
			IPs:           []string{"127.0.0.1", "127.0.0.2"},
			Ports:         []int{80, 443},
			Schemes:       []string{"http://www.example.com", "https://www.example.com"},
			Technologies:  []string{"nginx", "php", "wordpress"},
			Servers:       []string{"Apache"},
			Titles:        []string{"Admin Portal"},
			IsInteresting: true,
		},
	}

	summary := BuildSummary(assets)
	if summary.TotalAssets != 1 {
		t.Fatalf("unexpected total assets: %+v", summary)
	}
	if summary.UniqueIPs != 2 || summary.UniquePorts != 2 || summary.UniqueWebEndpoints != 2 {
		t.Fatalf("unexpected coverage summary: %+v", summary)
	}
	if summary.InterestingAssets != 1 {
		t.Fatalf("unexpected interesting count: %+v", summary)
	}
	if summary.EvidenceScore <= 0 || summary.EvidenceScore > 100 {
		t.Fatalf("unexpected evidence score: %+v", summary)
	}
	if len(summary.TopTechnologies) == 0 {
		t.Fatalf("expected technologies in summary: %+v", summary)
	}
}
