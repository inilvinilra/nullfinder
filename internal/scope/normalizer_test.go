package scope

import "testing"

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input      string
		wantDomain string
		wantRoot   string
	}{
		{"http://example.com", "example.com", "example.com"},
		{"https://sub.example.com/path?query=1", "sub.example.com", "example.com"},
		{"*.example.com", "example.com", "example.com"},
		{"  EXAMPLE.COM  ", "example.com", "example.com"},
		{"sub.domain.co.uk", "sub.domain.co.uk", "domain.co.uk"},
		{"127.0.0.1:8080", "127.0.0.1", "127.0.0.1"},
		{"[::1]:8080", "::1", "::1"},
		{"[2001:db8::1]", "2001:db8::1", "2001:db8::1"},
		{"http://[2001:db8::1]:8080/test", "2001:db8::1", "2001:db8::1"},
	}

	for _, tt := range tests {
		gotDomain, gotRoot := NormalizeDomain(tt.input)
		if gotDomain != tt.wantDomain || gotRoot != tt.wantRoot {
			t.Errorf("NormalizeDomain(%q) = (%q, %q); want (%q, %q)", tt.input, gotDomain, gotRoot, tt.wantDomain, tt.wantRoot)
		}
	}
}
