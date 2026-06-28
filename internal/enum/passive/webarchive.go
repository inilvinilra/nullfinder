package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"nullfinder/internal/config"
	"nullfinder/internal/scope"
)

// WebarchiveProvider implements PassiveProvider for fetching historic subdomains from Wayback Machine.
type WebarchiveProvider struct {
	BaseURL string // Allows overriding target API host for mocking in unit tests
}

func init() {
	Registry = append(Registry, &WebarchiveProvider{})
}

func (p *WebarchiveProvider) Name() string {
	return "webarchive"
}

func (p *WebarchiveProvider) Type() ProviderType {
	return ProviderPublicNoKey
}

func (p *WebarchiveProvider) RequiresAPIKey() bool {
	return false
}

func (p *WebarchiveProvider) Enabled(cfg *config.Config) bool {
	return cfg.Providers.WebArchive.Enabled
}

// Enumerate queries web.archive.org CDX API for historic URLs and extracts hostnames.
func (p *WebarchiveProvider) Enumerate(ctx context.Context, domain string) ([]SubdomainResult, error) {
	domain = strings.TrimPrefix(domain, "*.")
	baseURL := p.BaseURL
	if baseURL == "" {
		baseURL = "http://web.archive.org"
	}
	urlStr := fmt.Sprintf("%s/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", baseURL, domain)

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
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

	// CDX output=json returns a table structure: [["original"], ["http://url1"], ["http://url2"]]
	var results [][]string
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var list []SubdomainResult

	for i, row := range results {
		// Skip header row
		if i == 0 || len(row) < 1 {
			continue
		}

		rawURL := row[0]
		parsed, err := url.Parse(rawURL)
		var host string

		if err != nil || parsed.Host == "" {
			// Prepend http schema manually if missing, as url.Parse fails on scheme-less URLs
			if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
				parsed, err = url.Parse("http://" + rawURL)
			}
			if err == nil {
				host = parsed.Host
			} else {
				// Fallback naive parser
				host = rawURL
				if idx := strings.Index(host, "/"); idx != -1 {
					host = host[:idx]
				}
			}
		} else {
			host = parsed.Host
		}

		cleanName, _ := scope.NormalizeDomain(host)
		if cleanName == "" {
			continue
		}

		// Validate subdomain relation
		if cleanName != domain && !strings.HasSuffix(cleanName, "."+domain) {
			continue
		}

		if !seen[cleanName] {
			seen[cleanName] = true
			list = append(list, SubdomainResult{
				Subdomain:    cleanName,
				Source:       "webarchive",
				Confidence:   75,
				FirstSeen:    time.Now(),
				Provider:     "webarchive",
				ProviderType: ProviderPublicNoKey,
			})
		}
	}

	return list, nil
}
