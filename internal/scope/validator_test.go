package scope

import "testing"

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"api.example.com", true},
		{"*.example.com", true},
		{"-example.com", false},
		{"example-.com", false},
		{"example..com", false},
		{"a.b.c.d.e.f.g.h", true},
		{"too-long-label-too-long-label-too-long-label-too-long-label-too-long-label.com", false},
		{"", false},
		{"invalid_chars!@#.com", false},
	}

	for _, tt := range tests {
		got := IsValidDomain(tt.domain)
		if got != tt.want {
			t.Errorf("IsValidDomain(%q) = %v; want %v", tt.domain, got, tt.want)
		}
	}
}

func TestValidateTarget(t *testing.T) {
	tests := []struct {
		target *Target
		want   bool
	}{
		{&Target{Domain: "example.com", InScope: true}, true},
		{&Target{Domain: "example.com", InScope: false}, false},
		{&Target{Domain: "-invalid.com", InScope: true}, false},
		{nil, false},
	}

	for _, tt := range tests {
		got := ValidateTarget(tt.target)
		if got != tt.want {
			t.Errorf("ValidateTarget(%v) = %v; want %v", tt.target, got, tt.want)
		}
	}
}
