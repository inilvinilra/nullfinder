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

// CertSpotterProvider queries the SSLMate CertSpotter API for certificate transparency subdomains.
type CertSpotterProvider struct {
	BaseURL string
}

func init() {
	Registry = append(Registry, &CertSpotterProvider{})
}

func (p *CertSpotterProvider) Name() string         { return "certspotter" }
func (p *CertSpotterProvider) Type() ProviderType   { return ProviderPublicNoKey }
func (p *CertSpotterProvider) RequiresAPIKey() bool { return false }
func (p *CertSpotterProvider) Enabled(cfg *config.Config) bool {
	return cfg.Providers.CertSpotter.Enabled
}

type certSpotterResult struct {
	DNSNames []string `json:"dns_names"`
}

func (p *CertSpotterProvider) Enumerate(ctx context.Context, domain string) ([]SubdomainResult, error) {
	baseURL := p.BaseURL
	if baseURL == "" {
		baseURL = "https://api.certspotter.com"
	}
	url := fmt.Sprintf("%s/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", baseURL, domain)
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

	var data []certSpotterResult
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var results []SubdomainResult
	for _, entry := range data {
		for _, name := range entry.DNSNames {
			host, _ := scope.NormalizeDomain(strings.TrimSpace(name))
			if host == "" || (!strings.HasSuffix(host, "."+domain) && host != domain) {
				continue
			}
			if !seen[host] {
				seen[host] = true
				results = append(results, SubdomainResult{
					Subdomain: host, Source: "certspotter", Confidence: 90,
					FirstSeen: time.Now(), Provider: "certspotter", ProviderType: ProviderPublicNoKey,
				})
			}
		}
	}
	return results, nil
}
