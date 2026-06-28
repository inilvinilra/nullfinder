package scan

import (
	"testing"

	"nullfinder/internal/storage"
)

func TestCompareAssets(t *testing.T) {
	prev := []storage.AssetRecord{
		{
			Domain:  "sub1.example.com",
			Ports:   []int{80},
			Schemes: []string{"http://sub1.example.com"},
		},
	}

	next := []storage.AssetRecord{
		{
			Domain:  "sub1.example.com",
			Ports:   []int{80, 443},                                                  // Added port 443
			Schemes: []string{"http://sub1.example.com", "https://sub1.example.com"}, // Added scheme
		},
		{
			Domain:  "sub2.example.com", // Entirely new subdomain
			Ports:   []int{80},
			Schemes: []string{"http://sub2.example.com"},
		},
	}

	newSubs, newPorts, newWeb := CompareAssets(prev, next)

	if len(newSubs) != 1 || newSubs[0] != "sub2.example.com" {
		t.Errorf("expected new subdomain sub2.example.com, got %v", newSubs)
	}

	if len(newPorts) != 2 {
		t.Errorf("expected 2 new ports, got %d", len(newPorts))
	}

	if len(newWeb) != 2 {
		t.Errorf("expected 2 new web services, got %d", len(newWeb))
	}
}
