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

// CrtshProvider implements PassiveProvider for fetching subdomains from crt.sh.
type CrtshProvider struct {
	BaseURL string // Allows overriding target API host for mocking in unit tests
}

func init() {
	Registry = append(Registry, &CrtshProvider{})
}

func (p *CrtshProvider) Name() string {
	return "crtsh"
}

func (p *CrtshProvider) Type() ProviderType {
	return ProviderPublicNoKey
}

func (p *CrtshProvider) RequiresAPIKey() bool {
	return false
}

func (p *CrtshProvider) Enabled(cfg *config.Config) bool {
	return cfg.Providers.Crtsh.Enabled
}

type crtshResult struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

// Enumerate queries crt.sh for certificates containing subdomains of the target domain.
func (p *CrtshProvider) Enumerate(ctx context.Context, domain string) ([]SubdomainResult, error) {
	// Clean the query domain prefix just in case
	domain = strings.TrimPrefix(domain, "*.")
	baseURL := p.BaseURL
	if baseURL == "" {
		baseURL = "https://crt.sh"
	}
	url := fmt.Sprintf("%s/?q=%%.%s&output=json", baseURL, domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NullFinder/1.0")

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http error code: %d", resp.StatusCode)
	}

	var results []crtshResult
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var list []SubdomainResult

	for _, entry := range results {
		// crt.sh name_value can contain multiple domains delimited by newlines
		names := strings.Split(entry.NameValue, "\n")
		names = append(names, entry.CommonName)

		for _, name := range names {
			cleanName, _ := scope.NormalizeDomain(name)
			if cleanName == "" {
				continue
			}

			// Validate that the returned name is a valid subdomain of the queried domain
			if cleanName != domain && !strings.HasSuffix(cleanName, "."+domain) {
				continue
			}

			if !seen[cleanName] {
				seen[cleanName] = true
				list = append(list, SubdomainResult{
					Subdomain:    cleanName,
					Source:       "crtsh",
					Confidence:   85,
					FirstSeen:    time.Now(),
					Provider:     "crtsh",
					ProviderType: ProviderPublicNoKey,
				})
			}
		}
	}

	return list, nil
}
