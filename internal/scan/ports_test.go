package scan

import (
	"testing"

	"nullfinder/internal/dns"
)

func TestBuildPortScanTargetsDedupesResolvedAddresses(t *testing.T) {
	targets := BuildPortScanTargets(
		[]string{"a.example.com", "b.example.com", "c.example.com"},
		[]dns.ResolutionResult{
			{Domain: "a.example.com", IPs: []string{"192.0.2.10"}, Resolved: true},
			{Domain: "b.example.com", IPs: []string{"192.0.2.10"}, Resolved: true},
			{Domain: "c.example.com", IPs: []string{"192.0.2.11"}, Resolved: true},
		},
	)

	if len(targets) != 2 {
		t.Fatalf("expected 2 unique address targets, got %d: %#v", len(targets), targets)
	}
	if targets[0].Address != "192.0.2.10" {
		t.Fatalf("expected first target address 192.0.2.10, got %q", targets[0].Address)
	}
	if targets[1].Address != "192.0.2.11" {
		t.Fatalf("expected second target address 192.0.2.11, got %q", targets[1].Address)
	}
}

func TestBuildPortScanTargetsFallsBackToDomain(t *testing.T) {
	targets := BuildPortScanTargets([]string{"example.com"}, nil)

	if len(targets) != 1 {
		t.Fatalf("expected fallback target, got %d", len(targets))
	}
	if targets[0].Domain != "example.com" || targets[0].Address != "example.com" {
		t.Fatalf("unexpected fallback target: %#v", targets[0])
	}
}
