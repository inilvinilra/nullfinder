package local

import (
	"testing"
	"time"

	"nullfinder/internal/enum/passive"
	"nullfinder/internal/scope"
)

func TestDeduplicateAndFilter(t *testing.T) {
	matcher := scope.NewMatcher([]string{"example.com", "*.example.com"}, []string{"bad.example.com"})

	rawResults := []passive.SubdomainResult{
		{Subdomain: "api.example.com", Provider: "crtsh", ProviderType: passive.ProviderPublicNoKey, FirstSeen: time.Now()},
		{Subdomain: "api.example.com", Provider: "webarchive", ProviderType: passive.ProviderPublicNoKey, FirstSeen: time.Now()},
		{Subdomain: "dev.example.com", Provider: "crtsh", ProviderType: passive.ProviderPublicNoKey, FirstSeen: time.Now()},
		{Subdomain: "bad.example.com", Provider: "crtsh", ProviderType: passive.ProviderPublicNoKey, FirstSeen: time.Now()},
		{Subdomain: "evil.com", Provider: "crtsh", ProviderType: passive.ProviderPublicNoKey, FirstSeen: time.Now()},
	}

	assets := DeduplicateAndFilter(rawResults, matcher)

	if len(assets) != 2 {
		t.Fatalf("expected 2 in-scope assets, got %d: %+v", len(assets), assets)
	}

	var foundAPI, foundDev bool
	for _, asset := range assets {
		if asset.Subdomain == "api.example.com" {
			foundAPI = true
			if len(asset.Sources) != 2 {
				t.Errorf("expected 2 sources for api.example.com, got %d", len(asset.Sources))
			}
			// max(85, 75) + 10 = 95
			if asset.Confidence != 95 {
				t.Errorf("expected confidence 95 for api.example.com, got %d", asset.Confidence)
			}
		} else if asset.Subdomain == "dev.example.com" {
			foundDev = true
			if len(asset.Sources) != 1 {
				t.Errorf("expected 1 source for dev.example.com, got %d", len(asset.Sources))
			}
			// crtsh = 85
			if asset.Confidence != 85 {
				t.Errorf("expected confidence 85 for dev.example.com, got %d", asset.Confidence)
			}
		} else {
			t.Errorf("unexpected subdomain in result: %q", asset.Subdomain)
		}
	}

	if !foundAPI {
		t.Error("missing api.example.com from results")
	}
	if !foundDev {
		t.Error("missing dev.example.com from results")
	}
}
