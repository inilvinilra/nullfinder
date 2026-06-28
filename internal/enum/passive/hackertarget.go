package passive

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"nullfinder/internal/config"
	"nullfinder/internal/scope"
)

// HackerTargetProvider queries api.hackertarget.com/hostsearch
type HackerTargetProvider struct {
	BaseURL string
}

func init() {
	Registry = append(Registry, &HackerTargetProvider{})
}

func (p *HackerTargetProvider) Name() string         { return "hackertarget" }
func (p *HackerTargetProvider) Type() ProviderType   { return ProviderPublicNoKey }
func (p *HackerTargetProvider) RequiresAPIKey() bool { return false }
func (p *HackerTargetProvider) Enabled(cfg *config.Config) bool {
	return cfg.Providers.HackerTarget.Enabled
}

func (p *HackerTargetProvider) Enumerate(ctx context.Context, domain string) ([]SubdomainResult, error) {
	baseURL := p.BaseURL
	if baseURL == "" {
		baseURL = "https://api.hackertarget.com"
	}
	url := fmt.Sprintf("%s/hostsearch/?q=%s", baseURL, domain)
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var results []SubdomainResult

	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.SplitN(line, ",", 2)
		if len(parts) < 1 {
			continue
		}
		host, _ := scope.NormalizeDomain(strings.TrimSpace(parts[0]))
		if host == "" || (!strings.HasSuffix(host, "."+domain) && host != domain) {
			continue
		}
		if !seen[host] {
			seen[host] = true
			results = append(results, SubdomainResult{
				Subdomain: host, Source: "hackertarget", Confidence: 75,
				FirstSeen: time.Now(), Provider: "hackertarget", ProviderType: ProviderPublicNoKey,
			})
		}
	}
	return results, nil
}
