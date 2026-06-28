package passive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHackerTargetProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("example.com,1.1.1.1\nsub.example.com,2.2.2.2\ninvalid.com,3.3.3.3"))
	}))
	defer server.Close()

	p := &HackerTargetProvider{BaseURL: server.URL}
	res, err := p.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("HackerTarget error: %v", err)
	}
	if len(res) != 2 {
		t.Errorf("Expected 2 subdomains, got %d: %+v", len(res), res)
	}
}

func TestAnubisProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`["example.com", "sub.example.com", "other.com"]`))
	}))
	defer server.Close()

	p := &AnubisProvider{BaseURL: server.URL}
	res, err := p.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Anubis error: %v", err)
	}
	if len(res) != 2 {
		t.Errorf("Expected 2 subdomains, got %d: %+v", len(res), res)
	}
}

func TestAlienVaultProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`{"passive_dns": [{"hostname": "example.com"}, {"hostname": "sub.example.com"}, {"hostname": "other.com"}]}`))
	}))
	defer server.Close()

	p := &AlienVaultProvider{BaseURL: server.URL}
	res, err := p.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("AlienVault error: %v", err)
	}
	if len(res) != 2 {
		t.Errorf("Expected 2 subdomains, got %d: %+v", len(res), res)
	}
}

func TestThreatCrowdProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`{"subdomains": ["example.com", "sub.example.com", "other.com"]}`))
	}))
	defer server.Close()

	p := &ThreatCrowdProvider{BaseURL: server.URL}
	res, err := p.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("ThreatCrowd error: %v", err)
	}
	if len(res) != 2 {
		t.Errorf("Expected 2 subdomains, got %d: %+v", len(res), res)
	}
}

func TestCertSpotterProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`[{"dns_names": ["example.com", "sub.example.com", "other.com"]}]`))
	}))
	defer server.Close()

	p := &CertSpotterProvider{BaseURL: server.URL}
	res, err := p.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("CertSpotter error: %v", err)
	}
	if len(res) != 2 {
		t.Errorf("Expected 2 subdomains, got %d: %+v", len(res), res)
	}
}

func TestURLScanProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`{"results": [{"page": {"domain": "example.com"}}, {"page": {"domain": "sub.example.com"}}, {"page": {"domain": "other.com"}}]}`))
	}))
	defer server.Close()

	p := &URLScanProvider{BaseURL: server.URL}
	res, err := p.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("URLScan error: %v", err)
	}
	if len(res) != 2 {
		t.Errorf("Expected 2 subdomains, got %d: %+v", len(res), res)
	}
}

func TestCommonCrawlProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`{"url": "https://example.com/index.html"}
{"url": "http://sub.example.com/api"}
{"url": "https://other.com/foo"}
`))
	}))
	defer server.Close()

	p := &CommonCrawlProvider{BaseURL: server.URL}
	res, err := p.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("CommonCrawl error: %v", err)
	}
	if len(res) != 2 {
		t.Errorf("Expected 2 subdomains, got %d: %+v", len(res), res)
	}
}

func TestRapidDNSProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`<html>
<body>
<table>
<tr><td>example.com</td></tr>
<tr><td>sub.example.com</td></tr>
<tr><td>other.com</td></tr>
</table>
</body>
</html>`))
	}))
	defer server.Close()

	p := &RapidDNSProvider{BaseURL: server.URL}
	res, err := p.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("RapidDNS error: %v", err)
	}
	if len(res) != 2 {
		t.Errorf("Expected 2 subdomains, got %d: %+v", len(res), res)
	}
}

func TestTHCProvider(t *testing.T) {
	pagesCalled := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		pagesCalled++
		rw.WriteHeader(http.StatusOK)
		if pagesCalled == 1 {
			// First page
			_, _ = rw.Write([]byte(";;Subdomains For: example.com\n;;Next Page: " + server.URL + "/example.com?p=page2\nexample.com\nwww.example.com\n"))
		} else {
			// Second page
			_, _ = rw.Write([]byte(";;Subdomains For: example.com\nsub.example.com\n"))
		}
	}))
	defer server.Close()

	p := &THCProvider{BaseURL: server.URL}
	res, err := p.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("THC error: %v", err)
	}
	if len(res) != 3 {
		t.Errorf("Expected 3 subdomains, got %d: %+v", len(res), res)
	}
	if pagesCalled != 2 {
		t.Errorf("Expected 2 pages to be queried, got %d", pagesCalled)
	}
}
