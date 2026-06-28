package scope

import (
	"strings"
	"testing"
)

func TestParseTXTReader(t *testing.T) {
	input := `
# This is a comment
// Another comment
example.com
*.example.com
!bad.example.com
-worse.example.com
`

	inScope, outOfScope, err := parseTXTReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseTXTReader failed: %v", err)
	}

	wantInScope := []string{"example.com", "*.example.com"}
	wantOutOfScope := []string{"bad.example.com", "worse.example.com"}

	if len(inScope) != len(wantInScope) {
		t.Errorf("inScope count = %d; want %d", len(inScope), len(wantInScope))
	}
	for i, v := range wantInScope {
		if i < len(inScope) && inScope[i] != v {
			t.Errorf("inScope[%d] = %q; want %q", i, inScope[i], v)
		}
	}

	if len(outOfScope) != len(wantOutOfScope) {
		t.Errorf("outOfScope count = %d; want %d", len(outOfScope), len(wantOutOfScope))
	}
	for i, v := range wantOutOfScope {
		if i < len(outOfScope) && outOfScope[i] != v {
			t.Errorf("outOfScope[%d] = %q; want %q", i, outOfScope[i], v)
		}
	}
}

func TestParseJSONScope(t *testing.T) {
	input := `{
		"in_scope": ["example.com", "*.example.com"],
		"out_of_scope": ["bad.example.com"]
	}`

	inScope, outOfScope, err := parseJSONScope(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseJSONScope failed: %v", err)
	}

	if len(inScope) != 2 || inScope[0] != "example.com" {
		t.Errorf("unexpected inScope: %v", inScope)
	}
	if len(outOfScope) != 1 || outOfScope[0] != "bad.example.com" {
		t.Errorf("unexpected outOfScope: %v", outOfScope)
	}
}

func TestParseRawTarget(t *testing.T) {
	m := NewMatcher([]string{"example.com", "*.example.com"}, []string{"bad.example.com"})

	t1 := ParseRawTarget("https://api.example.com/login", m, "test")
	if t1 == nil {
		t.Fatal("ParseRawTarget returned nil")
	}

	if t1.Domain != "api.example.com" || t1.RootDomain != "example.com" || !t1.InScope || t1.Source != "test" {
		t.Errorf("unexpected parsed target: %+v", t1)
	}

	t2 := ParseRawTarget("bad.example.com", m, "test")
	if t2 == nil {
		t.Fatal("ParseRawTarget returned nil")
	}
	if t2.InScope {
		t.Error("bad.example.com should be marked out of scope")
	}
}
