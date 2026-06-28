package passive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebarchiveEnumerate(t *testing.T) {
	// Wayback Machine CDX output=json table format mock
	mockJSON := `[
		["original"],
		["http://api.example.com/index.html"],
		["https://dev.example.com/login?u=1"],
		["http://example.com/test"],
		["https://evil.com/leak"]
	]`

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(mockJSON))
	}))
	defer server.Close()

	prov := &WebarchiveProvider{
		BaseURL: server.URL,
	}

	results, err := prov.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("failed to enumerate: %v", err)
	}

	// Expecting: api.example.com, dev.example.com, and example.com (root domain itself is valid)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d: %+v", len(results), results)
	}

	var foundAPI, foundDev, foundRoot bool
	for _, r := range results {
		if r.Subdomain == "api.example.com" {
			foundAPI = true
		} else if r.Subdomain == "dev.example.com" {
			foundDev = true
		} else if r.Subdomain == "example.com" {
			foundRoot = true
		}
	}

	if !foundAPI {
		t.Error("missing api.example.com")
	}
	if !foundDev {
		t.Error("missing dev.example.com")
	}
	if !foundRoot {
		t.Error("missing example.com")
	}
}
