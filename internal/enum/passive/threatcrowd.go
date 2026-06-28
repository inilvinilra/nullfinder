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

// ThreatCrowdProvider queries the ThreatCrowd API for subdomains.
type ThreatCrowdProvider struct {
	BaseURL string
}

func init() {
	Registry = append(Registry, &ThreatCrowdProvider{})
}

func (p *ThreatCrowdProvider) Name() string         { return "threatcrowd" }
func (p *ThreatCrowdProvider) Type() ProviderType   { return ProviderPublicNoKey }
func (p *ThreatCrowdProvider) RequiresAPIKey() bool { return false }
func (p *ThreatCrowdProvider) Enabled(cfg *config.Config) bool {
	return cfg.Providers.ThreatCrowd.Enabled
}

type threatCrowdResponse struct {
	Subdomains []string `json:"subdomains"`
}

func (p *ThreatCrowdProvider) Enumerate(ctx context.Context, domain string) ([]SubdomainResult, error) {
	baseURL := p.BaseURL
	if baseURL == "" {
		baseURL = "https://www.threatcrowd.org"
	}
	url := fmt.Sprintf("%s/searchApi/v2/domain/report/?domain=%s", baseURL, domain)
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

	var data threatCrowdResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var results []SubdomainResult
	for _, s := range data.Subdomains {
		host, _ := scope.NormalizeDomain(strings.TrimSpace(s))
		if host == "" || (!strings.HasSuffix(host, "."+domain) && host != domain) {
			continue
		}
		if !seen[host] {
			seen[host] = true
			results = append(results, SubdomainResult{
				Subdomain: host, Source: "threatcrowd", Confidence: 70,
				FirstSeen: time.Now(), Provider: "threatcrowd", ProviderType: ProviderPublicNoKey,
			})
		}
	}
	return results, nil
}
