package passive

import (
	"context"
	"errors"
	"testing"

	"nullfinder/internal/config"
)

type retryProvider struct {
	attempts int
}

func (p *retryProvider) Name() string                    { return "retry" }
func (p *retryProvider) Type() ProviderType              { return ProviderPublicNoKey }
func (p *retryProvider) RequiresAPIKey() bool            { return false }
func (p *retryProvider) Enabled(cfg *config.Config) bool { return true }
func (p *retryProvider) Enumerate(ctx context.Context, domain string) ([]SubdomainResult, error) {
	p.attempts++
	if p.attempts < 3 {
		return nil, errors.New("http error code: 502")
	}
	return []SubdomainResult{{Subdomain: "api." + domain, Provider: "retry"}}, nil
}

func TestEnumerateWithRetry(t *testing.T) {
	p := &retryProvider{}
	results, err := enumerateWithRetry(context.Background(), p, "example.com")
	if err != nil {
		t.Fatalf("expected retry to succeed, got error: %v", err)
	}
	if p.attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", p.attempts)
	}
	if len(results) != 1 || results[0].Subdomain != "api.example.com" {
		t.Fatalf("unexpected retry results: %+v", results)
	}
}

func TestIsRetryableProviderError(t *testing.T) {
	if !isRetryableProviderError(errors.New("http error: 429")) {
		t.Fatal("expected 429 to be retryable")
	}
	if isRetryableProviderError(errors.New("invalid API key")) {
		t.Fatal("expected credential error to be non-retryable")
	}
}
