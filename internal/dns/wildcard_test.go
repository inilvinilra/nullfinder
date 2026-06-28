package dns

import (
	"context"
	"strings"
	"testing"
)

type MockResolver struct {
	resolvedIPs map[string][]string
}

func (m *MockResolver) ResolveSingle(ctx context.Context, domain string) ResolutionResult {
	// If direct match
	if ips, ok := m.resolvedIPs[domain]; ok {
		return ResolutionResult{Domain: domain, IPs: ips, Resolved: true}
	}
	// If it's a randomized wildcard query (e.g. nullfinder-rand-f4a21d.wildcard.com)
	if strings.HasPrefix(domain, "nullfinder-rand-") {
		// Extract base domain
		parts := strings.SplitN(domain, ".", 2)
		if len(parts) == 2 {
			parent := parts[1]
			if ips, ok := m.resolvedIPs["*."+parent]; ok {
				return ResolutionResult{Domain: domain, IPs: ips, Resolved: true}
			}
		}
	}
	return ResolutionResult{Domain: domain, Resolved: false}
}

func (m *MockResolver) ResolveBatch(ctx context.Context, domains []string) []ResolutionResult {
	var results []ResolutionResult
	for _, d := range domains {
		results = append(results, m.ResolveSingle(ctx, d))
	}
	return results
}

func TestWildcardDetection(t *testing.T) {
	mock := &MockResolver{
		resolvedIPs: map[string][]string{
			"*.wildcard.com":      {"192.168.1.100"},
			"api.nonwildcard.com": {"192.168.1.1"},
		},
	}

	detector := NewWildcardDetector(mock)

	// Test wildcard.com
	isWildcard := detector.Detect(context.Background(), "wildcard.com")
	if !isWildcard {
		t.Error("expected wildcard.com to be flagged as wildcard DNS")
	}

	// Test nonwildcard.com
	isNotWildcard := detector.Detect(context.Background(), "nonwildcard.com")
	if isNotWildcard {
		t.Error("expected nonwildcard.com NOT to be flagged as wildcard DNS")
	}

	// Check IsWildcardIP
	if !detector.IsWildcardIP("api.wildcard.com", []string{"192.168.1.100"}) {
		t.Error("expected 192.168.1.100 to be wildcard IP for wildcard.com")
	}

	if detector.IsWildcardIP("api.nonwildcard.com", []string{"192.168.1.1"}) {
		t.Error("expected 192.168.1.1 NOT to be wildcard IP")
	}
}
