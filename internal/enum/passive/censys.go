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

// CensysProvider implements PassiveProvider for Censys.
type CensysProvider struct {
	BaseURL string
}

func init() {
	Registry = append(Registry, &CensysProvider{})
}

func (p *CensysProvider) Name() string {
	return "censys"
}

func (p *CensysProvider) Type() ProviderType {
	return ProviderAPIKey
}

func (p *CensysProvider) RequiresAPIKey() bool {
	return true
}

func (p *CensysProvider) Enabled(cfg *config.Config) bool {
	return cfg.Providers.Censys.Enabled
}

type censysHit struct {
	Names []string `json:"names"`
}

type censysResult struct {
	Hits []censysHit `json:"hits"`
}

type censysResponse struct {
	Code   int          `json:"code"`
	Status string       `json:"status"`
	Result censysResult `json:"result"`
}

// Enumerate queries the Censys V2 Certificates search endpoint.
func (p *CensysProvider) Enumerate(ctx context.Context, domain string) ([]SubdomainResult, error) {
	apiID, apiSecret := censysCredentials()
	if apiID == "" || apiSecret == "" {
		return nil, fmt.Errorf("missing CENSYS_API_ID or CENSYS_API_SECRET environment variables")
	}

	domain = strings.TrimPrefix(domain, "*.")
	baseURL := p.BaseURL
	if baseURL == "" {
		baseURL = "https://search.censys.io/api/v2"
	}
	url := fmt.Sprintf("%s/certificates/search?q=%s&per_page=100", baseURL, domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(apiID, apiSecret)
	req.Header.Set("Accept", "application/json")
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("invalid Censys credentials or unauthorized response: status %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http error code: %d", resp.StatusCode)
	}

	var res censysResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var list []SubdomainResult

	for _, hit := range res.Result.Hits {
		for _, name := range hit.Names {
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
					Source:       "censys",
					Confidence:   90,
					FirstSeen:    time.Now(),
					Provider:     "censys",
					ProviderType: ProviderAPIKey,
				})
			}
		}
	}

	return list, nil
}
