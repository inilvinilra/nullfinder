package scan

import (
	"testing"

	"nullfinder/internal/config"
)

func TestResolveDiscoverySettings(t *testing.T) {
	cfg := &config.Config{}
	cfg.Enum.LocalWordlistEnabled = true
	cfg.Enum.LocalPermutationEnabled = false
	cfg.Scan.MaxDepth = 2

	settings := ResolveDiscoverySettings("hybrid", cfg, false, false, 0)
	if !settings.PassiveEnabled || !settings.WordlistEnabled {
		t.Fatalf("expected passive and wordlist discovery enabled, got %+v", settings)
	}
	if settings.PermutationEnabled {
		t.Fatalf("expected permutations disabled by config, got %+v", settings)
	}
	if settings.MaxDepth != 2 {
		t.Fatalf("expected max depth from config, got %d", settings.MaxDepth)
	}

	activeOnly := ResolveDiscoverySettings("passive", cfg, true, false, 3)
	if activeOnly.PassiveEnabled {
		t.Fatalf("expected passive discovery disabled when forcing active mode, got %+v", activeOnly)
	}
	if !activeOnly.WordlistEnabled || !activeOnly.PermutationEnabled || activeOnly.MaxDepth != 3 {
		t.Fatalf("unexpected active-only settings: %+v", activeOnly)
	}
}
