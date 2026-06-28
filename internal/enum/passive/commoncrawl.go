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

// CommonCrawlProvider queries the CommonCrawl index API for subdomains.
type CommonCrawlProvider struct {
	BaseURL string
}

func init() {
	Registry = append(Registry, &CommonCrawlProvider{})
}

func (p *CommonCrawlProvider) Name() string         { return "commoncrawl" }
func (p *CommonCrawlProvider) Type() ProviderType   { return ProviderPublicNoKey }
func (p *CommonCrawlProvider) RequiresAPIKey() bool { return false }
func (p *CommonCrawlProvider) Enabled(cfg *config.Config) bool {
	return cfg.Providers.CommonCrawl.Enabled
}

type commonCrawlResult struct {
	URL string `json:"url"`
}

type commonCrawlCollection struct {
	ID string `json:"id"`
}

func (p *CommonCrawlProvider) indexID(ctx context.Context, baseURL string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/collinfo.json", baseURL), nil)
	if err != nil {
		return "CC-MAIN-2024-10-index"
	}

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return "CC-MAIN-2024-10-index"
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "CC-MAIN-2024-10-index"
	}

	var collections []commonCrawlCollection
	if err := json.NewDecoder(resp.Body).Decode(&collections); err != nil {
		return "CC-MAIN-2024-10-index"
	}
	if len(collections) == 0 || collections[0].ID == "" {
		return "CC-MAIN-2024-10-index"
	}

	return collections[0].ID + "-index"
}

func (p *CommonCrawlProvider) Enumerate(ctx context.Context, domain string) ([]SubdomainResult, error) {
	baseURL := p.BaseURL
	if baseURL == "" {
		baseURL = "https://index.commoncrawl.org"
	}
	url := fmt.Sprintf("%s/%s?url=*.%s&output=json&limit=500", baseURL, p.indexID(ctx, baseURL), domain)
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

	// CommonCrawl returns NDJSON (newline-delimited JSON)
	decoder := json.NewDecoder(resp.Body)
	seen := make(map[string]bool)
	var results []SubdomainResult

	for decoder.More() {
		var entry commonCrawlResult
		if err := decoder.Decode(&entry); err != nil {
			continue
		}

		// Extract hostname from URL
		u := entry.URL
		u = strings.TrimPrefix(u, "http://")
		u = strings.TrimPrefix(u, "https://")
		if idx := strings.Index(u, "/"); idx != -1 {
			u = u[:idx]
		}
		if idx := strings.Index(u, ":"); idx != -1 {
			u = u[:idx]
		}

		host, _ := scope.NormalizeDomain(strings.TrimSpace(u))
		if host == "" || (!strings.HasSuffix(host, "."+domain) && host != domain) {
			continue
		}
		if !seen[host] {
			seen[host] = true
			results = append(results, SubdomainResult{
				Subdomain: host, Source: "commoncrawl", Confidence: 70,
				FirstSeen: time.Now(), Provider: "commoncrawl", ProviderType: ProviderPublicNoKey,
			})
		}
	}
	return results, nil
}
