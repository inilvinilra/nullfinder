package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nullfinder/internal/config"
)

func TestAPIServerRouting(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Path = t.TempDir() + "/test.db"

	srv := NewServer("127.0.0.1", 8080, cfg, t.TempDir())

	// Test GET / (Dashboard)
	req, _ := http.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleDashboard(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Test GET /api/scans
	req, _ = http.NewRequest("GET", "/api/scans", nil)
	rr = httptest.NewRecorder()
	srv.handleScans(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Test POST /api/scans validation
	body := `{"domain": ""}`
	req, _ = http.NewRequest("POST", "/api/scans", strings.NewReader(body))
	rr = httptest.NewRecorder()
	srv.handleScans(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for empty domain, got %d", rr.Code)
	}
}
