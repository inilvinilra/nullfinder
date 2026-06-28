package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"nullfinder/internal/config"
	"nullfinder/internal/scope"
)

// AnubisProvider queries the jldc.me Anubis API for subdomain enumeration.
type AnubisProvider struct {
	BaseURL string
}

func init() {
	Registry = append(Registry, &AnubisProvider{})
}

func (p *AnubisProvider) Name() string                    { return "anubis" }
func (p *AnubisProvider) Type() ProviderType              { return ProviderPublicNoKey }
func (p *AnubisProvider) RequiresAPIKey() bool            { return false }
func (p *AnubisProvider) Enabled(cfg *config.Config) bool { return cfg.Providers.Anubis.Enabled }

func (p *AnubisProvider) Enumerate(ctx context.Context, domain string) ([]SubdomainResult, error) {
	baseURL := p.BaseURL
	if baseURL == "" {
		baseURL = "https://jonlu.ca"
	}
	url := fmt.Sprintf("%s/anubis/subdomains/%s", baseURL, domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "NullFinder/1.0")

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http error: %d", resp.StatusCode)
	}

	var subs []string
	if err := json.NewDecoder(resp.Body).Decode(&subs); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var results []SubdomainResult
	for _, s := range subs {
		host, _ := scope.NormalizeDomain(strings.TrimSpace(s))
		if host == "" || (!strings.HasSuffix(host, "."+domain) && host != domain) {
			continue
		}
		if !seen[host] {
			seen[host] = true
			results = append(results, SubdomainResult{
				Subdomain: host, Source: "anubis", Confidence: 80,
				FirstSeen: time.Now(), Provider: "anubis", ProviderType: ProviderPublicNoKey,
			})
		}
	}
	return results, nil
}
