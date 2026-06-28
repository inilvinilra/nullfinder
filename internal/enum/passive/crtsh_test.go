package passive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestCrtshEnumerate(t *testing.T) {
	// Read fixture file
	data, err := os.ReadFile("../../../tests/fixtures/provider_crtsh_sample.json")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	// Start local mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write(data)
	}))
	defer server.Close()

	prov := &CrtshProvider{
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
