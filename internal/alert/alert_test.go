package alert

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"nullfinder/internal/config"
)

func TestSendAlert(t *testing.T) {
	var receivedPayload AlertPayload
	var called bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_ = json.NewDecoder(r.Body).Decode(&receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Alerting.CustomWebhookURL = server.URL

	newSubs := []string{"new.example.com"}
	newPorts := []string{"new.example.com:443"}
	newWeb := []string{"https://new.example.com"}

	err := SendAlert(cfg, "example.com", newSubs, newPorts, newWeb)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !called {
		t.Errorf("expected webhook mock to be called")
	}

	if receivedPayload.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", receivedPayload.Domain)
	}

	if len(receivedPayload.NewSubs) != 1 || receivedPayload.NewSubs[0] != "new.example.com" {
		t.Errorf("expected subdomain new.example.com, got %v", receivedPayload.NewSubs)
	}
}
