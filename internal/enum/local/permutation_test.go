package local

import (
	"testing"

	"nullfinder/internal/scope"
)

func TestGeneratePermutations(t *testing.T) {
	subdomains := []string{"api.example.com", "dev-app.example.com"}
	matcher := scope.NewMatcher([]string{"*.example.com"}, []string{"stage-api.example.com"})

	candidates := GeneratePermutations(subdomains, matcher)

	candidatesMap := make(map[string]bool)
	for _, c := range candidates {
		candidatesMap[c] = true
	}

	// Prepend/append check
	if !candidatesMap["dev-api.example.com"] {
		t.Error("expected dev-api.example.com to be generated")
	}

	// Out of scope check
	if candidatesMap["stage-api.example.com"] {
		t.Error("stage-api.example.com should have been excluded")
	}

	// Digit suffix check
	if !candidatesMap["api1.example.com"] {
		t.Error("expected api1.example.com to be generated")
	}

	// Delimiter swap check
	if !candidatesMap["dev.app.example.com"] {
		t.Error("expected dev.app.example.com to be generated")
	}

	// Delimiter removal check
	if !candidatesMap["devapp.example.com"] {
		t.Error("expected devapp.example.com to be generated")
	}

	// Label simplification check
	subdomains = []string{"stdwebsrv1.example.com"}
	candidates = GeneratePermutations(subdomains, scope.NewMatcher([]string{"*.example.com"}, nil))
	candidatesMap = make(map[string]bool)
	for _, c := range candidates {
		candidatesMap[c] = true
	}
	if !candidatesMap["stdweb1.example.com"] {
		t.Error("expected stdweb1.example.com to be generated from simplified label")
	}
}
