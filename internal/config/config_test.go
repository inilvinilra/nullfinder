package config

import (
	"testing"
)

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.Mode != "hybrid" {
		t.Errorf("cfg.Mode = %q; want %q", cfg.Mode, "hybrid")
	}

	if cfg.Scan.Threads != 25 {
		t.Errorf("cfg.Scan.Threads = %d; want %d", cfg.Scan.Threads, 25)
	}

	if cfg.Providers.Crtsh.Enabled != true {
		t.Errorf("cfg.Providers.Crtsh.Enabled = %v; want true", cfg.Providers.Crtsh.Enabled)
	}

	if cfg.DNS.ResolverMode != "mixed" {
		t.Errorf("cfg.DNS.ResolverMode = %q; want %q", cfg.DNS.ResolverMode, "mixed")
	}
}
