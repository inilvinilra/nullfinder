package local

import (
	"os"
	"path/filepath"
	"testing"

	"nullfinder/internal/scope"
)

func TestGenerateWordlistCandidates(t *testing.T) {
	tmpDir := t.TempDir()
	wordlistPath := filepath.Join(tmpDir, "test_wordlist.txt")
	content := `
www
api
# comment
dev
`
	if err := os.WriteFile(wordlistPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test wordlist: %v", err)
	}

	inScope := []string{"*.example.com", "*.target.org"}
	matcher := scope.NewMatcher(inScope, []string{"dev.example.com"})

	candidates, err := GenerateWordlistCandidates(wordlistPath, inScope, matcher)
	if err != nil {
		t.Fatalf("failed to generate candidates: %v", err)
	}

	expected := map[string]bool{
		"www.example.com": true,
		"api.example.com": true,
		"www.target.org":  true,
		"api.target.org":  true,
		"dev.target.org":  true,
	}

	for _, cand := range candidates {
		if !expected[cand] {
			t.Errorf("unexpected candidate: %q", cand)
		}
		delete(expected, cand)
	}

	if len(expected) > 0 {
		t.Errorf("missing expected candidates: %v", expected)
	}
}
