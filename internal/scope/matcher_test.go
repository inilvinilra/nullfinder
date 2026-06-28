package scope

import "testing"

func TestMatchDomain(t *testing.T) {
	tests := []struct {
		domain  string
		pattern string
		want    bool
	}{
		{"example.com", "example.com", true},
		{"api.example.com", "*.example.com", true},
		{"dev.api.example.com", "*.example.com", true},
		{"example.com", "*.example.com", true},
		{"example.com.evil.com", "example.com", false},
		{"example.com.evil.com", "*.example.com", false},
		{"notexample.com", "example.com", false},
		{"notexample.com", "*.example.com", false},
	}

	for _, tt := range tests {
		got := MatchDomain(tt.domain, tt.pattern)
		if got != tt.want {
			t.Errorf("MatchDomain(%q, %q) = %v; want %v", tt.domain, tt.pattern, got, tt.want)
		}
	}
}

func TestMatcherIsInScope(t *testing.T) {
	inScope := []string{"example.com", "*.example.com", "target.org"}
	outOfScope := []string{"out.example.com", "*.out.example.com"}

	m := NewMatcher(inScope, outOfScope)

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"api.example.com", true},
		{"target.org", true},
		{"sub.target.org", false}, // Exact match only for target.org
		{"out.example.com", false},
		{"api.out.example.com", false},
		{"example.com.evil.com", false},
	}

	for _, tt := range tests {
		got := m.IsInScope(tt.domain)
		if got != tt.want {
			t.Errorf("Matcher.IsInScope(%q) = %v; want %v", tt.domain, got, tt.want)
		}
	}
}
