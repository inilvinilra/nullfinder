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

// SecurityTrailsProvider implements PassiveProvider for SecurityTrails.
type SecurityTrailsProvider struct {
	BaseURL string
}

func init() {
	Registry = append(Registry, &SecurityTrailsProvider{})
}

func (p *SecurityTrailsProvider) Name() string {
	return "securitytrails"
}

func (p *SecurityTrailsProvider) Type() ProviderType {
	return ProviderAPIKey
}

func (p *SecurityTrailsProvider) RequiresAPIKey() bool {
	return true
}

func (p *SecurityTrailsProvider) Enabled(cfg *config.Config) bool {
	return cfg.Providers.SecurityTrails.Enabled
}

type stResult struct {
	Subdomains []string `json:"subdomains"`
}

// Enumerate queries the SecurityTrails API for subdomains.
func (p *SecurityTrailsProvider) Enumerate(ctx context.Context, domain string) ([]SubdomainResult, error) {
	apiKey := securityTrailsAPIKey()
	if apiKey == "" {
		return nil, fmt.Errorf("missing SECURITYTRAILS_API_KEY environment variable")
	}

	domain = strings.TrimPrefix(domain, "*.")
	baseURL := p.BaseURL
	if baseURL == "" {
		baseURL = "https://api.securitytrails.com/v1"
	}
	url := fmt.Sprintf("%s/domain/%s/subdomains", baseURL, domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("APIKEY", apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("invalid API key or unauthorized response: status %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http error code: %d", resp.StatusCode)
	}

	var result stResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var list []SubdomainResult

	for _, sub := range result.Subdomains {
		fullName := fmt.Sprintf("%s.%s", sub, domain)
		cleanName, _ := scope.NormalizeDomain(fullName)
		if cleanName == "" {
			continue
		}

		if !seen[cleanName] {
			seen[cleanName] = true
			list = append(list, SubdomainResult{
				Subdomain:    cleanName,
				Source:       "securitytrails",
				Confidence:   95,
				FirstSeen:    time.Now(),
				Provider:     "securitytrails",
				ProviderType: ProviderAPIKey,
			})
		}
	}

	return list, nil
}
