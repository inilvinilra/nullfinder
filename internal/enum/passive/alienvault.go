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

// AlienVaultProvider queries otx.alienvault.com passive DNS records.
type AlienVaultProvider struct {
	BaseURL string
}

func init() {
	Registry = append(Registry, &AlienVaultProvider{})
}

func (p *AlienVaultProvider) Name() string         { return "alienvault" }
func (p *AlienVaultProvider) Type() ProviderType   { return ProviderPublicNoKey }
func (p *AlienVaultProvider) RequiresAPIKey() bool { return false }
func (p *AlienVaultProvider) Enabled(cfg *config.Config) bool {
	return cfg.Providers.AlienVault.Enabled
}

type otxPassiveDNSResponse struct {
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
}

func (p *AlienVaultProvider) Enumerate(ctx context.Context, domain string) ([]SubdomainResult, error) {
	baseURL := p.BaseURL
	if baseURL == "" {
		baseURL = "https://otx.alienvault.com"
	}
	url := fmt.Sprintf("%s/api/v1/indicators/domain/%s/passive_dns", baseURL, domain)
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

	var data otxPassiveDNSResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var results []SubdomainResult
	for _, entry := range data.PassiveDNS {
		host, _ := scope.NormalizeDomain(strings.TrimSpace(entry.Hostname))
		if host == "" || (!strings.HasSuffix(host, "."+domain) && host != domain) {
			continue
		}
		if !seen[host] {
			seen[host] = true
			results = append(results, SubdomainResult{
				Subdomain: host, Source: "alienvault", Confidence: 80,
				FirstSeen: time.Now(), Provider: "alienvault", ProviderType: ProviderPublicNoKey,
			})
		}
	}
	return results, nil
}
