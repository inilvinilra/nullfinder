package httpprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestProberSingle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "text/html")
		rw.Header().Set("Server", "Apache-Test")
		rw.Header().Set("X-Powered-By", "PHP/8.2")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`<html><head><title>My Test Site</title><meta name="generator" content="WordPress 6.5"></head><body>Hello wordpress</body></html>`))
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}

	// Extract host and port
	var host string
	var port int
	if idx := strings.Index(u.Host, ":"); idx != -1 {
		host = u.Host[:idx]
		port, _ = strconv.Atoi(u.Host[idx+1:])
	} else {
		host = u.Host
		if u.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}

	prober := NewProber([]int{port}, 1, 0, 2, false, 2, []string{})
	res := prober.ProbeSingle(context.Background(), u.Scheme, host, port)

	if res == nil {
		t.Fatalf("expected successful probe, got nil")
	}

	if res.Title != "My Test Site" {
		t.Errorf("expected Title to be 'My Test Site', got %q", res.Title)
	}

	if res.Server != "Apache-Test" {
		t.Errorf("expected Server to be 'Apache-Test', got %q", res.Server)
	}

	if res.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", res.StatusCode)
	}

	if res.FinalURL == "" {
		t.Errorf("expected final URL to be populated")
	}

	if res.ResolvedAddress == "" || res.ResolvedIP == "" {
		t.Errorf("expected resolved address/ip to be populated, got addr=%q ip=%q", res.ResolvedAddress, res.ResolvedIP)
	}

	if res.RedirectCount != 0 {
		t.Errorf("expected zero redirects, got %d", res.RedirectCount)
	}

	if res.ContentType != "text/html" {
		t.Errorf("expected content type to be 'text/html', got %q", res.ContentType)
	}

	if res.PoweredBy != "PHP/8.2" {
		t.Errorf("expected powered by to be 'PHP/8.2', got %q", res.PoweredBy)
	}

	if len(res.Technologies) == 0 {
		t.Errorf("expected technology hints to be populated")
	}
}
