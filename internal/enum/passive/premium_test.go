package passive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestSecurityTrailsEnumerate(t *testing.T) {
	_ = os.Setenv("SECURITYTRAILS_API_KEY", "test-key")
	defer os.Unsetenv("SECURITYTRAILS_API_KEY")

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.Header.Get("APIKEY") != "test-key" {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`{"subdomains": ["api", "dev"]}`))
	}))
	defer server.Close()

	prov := &SecurityTrailsProvider{BaseURL: server.URL}
	results, err := prov.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("failed to enumerate: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 subdomains, got %d", len(results))
	}
	if results[0].Subdomain != "api.example.com" || results[1].Subdomain != "dev.example.com" {
		t.Errorf("unexpected results: %+v", results)
	}
}

func TestShodanEnumerate(t *testing.T) {
	_ = os.Setenv("SHODAN_API_KEY", "test-key")
	defer os.Unsetenv("SHODAN_API_KEY")

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Query().Get("key") != "test-key" {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`{"subdomains": ["admin", "mail"]}`))
	}))
	defer server.Close()

	prov := &ShodanProvider{BaseURL: server.URL}
	results, err := prov.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("failed to enumerate: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 subdomains, got %d", len(results))
	}
	if results[0].Subdomain != "admin.example.com" || results[1].Subdomain != "mail.example.com" {
		t.Errorf("unexpected results: %+v", results)
	}
}

func TestCensysEnumerate(t *testing.T) {
	_ = os.Setenv("CENSYS_API_ID", "test-id")
	_ = os.Setenv("CENSYS_API_SECRET", "test-secret")
	defer os.Unsetenv("CENSYS_API_ID")
	defer os.Unsetenv("CENSYS_API_SECRET")

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		username, password, ok := req.BasicAuth()
		if !ok || username != "test-id" || password != "test-secret" {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`{
			"code": 200,
			"status": "OK",
			"result": {
				"hits": [
					{
						"names": ["www.example.com", "mail.example.com"]
					}
				]
			}
		}`))
	}))
	defer server.Close()

	prov := &CensysProvider{BaseURL: server.URL}
	results, err := prov.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("failed to enumerate: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 subdomains, got %d", len(results))
	}
	if results[0].Subdomain != "www.example.com" || results[1].Subdomain != "mail.example.com" {
		t.Errorf("unexpected results: %+v", results)
	}
}
