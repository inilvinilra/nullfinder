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

// URLScanProvider queries urlscan.io search API for subdomains.
type URLScanProvider struct {
	BaseURL string
}

func init() {
	Registry = append(Registry, &URLScanProvider{})
}

func (p *URLScanProvider) Name() string                    { return "urlscan" }
func (p *URLScanProvider) Type() ProviderType              { return ProviderPublicNoKey }
func (p *URLScanProvider) RequiresAPIKey() bool            { return false }
func (p *URLScanProvider) Enabled(cfg *config.Config) bool { return cfg.Providers.URLScan.Enabled }

type urlscanResponse struct {
	Results []struct {
		Page struct {
			Domain string `json:"domain"`
		} `json:"page"`
	} `json:"results"`
}

func (p *URLScanProvider) Enumerate(ctx context.Context, domain string) ([]SubdomainResult, error) {
	baseURL := p.BaseURL
	if baseURL == "" {
		baseURL = "https://urlscan.io"
	}
	url := fmt.Sprintf("%s/api/v1/search/?q=domain:%s&size=1000", baseURL, domain)
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

	var data urlscanResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var results []SubdomainResult
	for _, r := range data.Results {
		host, _ := scope.NormalizeDomain(strings.TrimSpace(r.Page.Domain))
		if host == "" || (!strings.HasSuffix(host, "."+domain) && host != domain) {
			continue
		}
		if !seen[host] {
			seen[host] = true
			results = append(results, SubdomainResult{
				Subdomain: host, Source: "urlscan", Confidence: 75,
				FirstSeen: time.Now(), Provider: "urlscan", ProviderType: ProviderPublicNoKey,
			})
		}
	}
	return results, nil
}
