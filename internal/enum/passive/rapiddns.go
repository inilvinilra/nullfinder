package passive

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"nullfinder/internal/config"
	"nullfinder/internal/scope"
)

// RapidDNSProvider scrapes subdomains from RapidDNS.io
type RapidDNSProvider struct {
	BaseURL string
}

func init() {
	Registry = append(Registry, &RapidDNSProvider{})
}

func (p *RapidDNSProvider) Name() string                    { return "rapiddns" }
func (p *RapidDNSProvider) Type() ProviderType              { return ProviderPublicNoKey }
func (p *RapidDNSProvider) RequiresAPIKey() bool            { return false }
func (p *RapidDNSProvider) Enabled(cfg *config.Config) bool { return cfg.Providers.RapidDNS.Enabled }

var rapiddnsRegex = regexp.MustCompile(`(?i)<td>([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})</td>`)

func (p *RapidDNSProvider) Enumerate(ctx context.Context, domain string) ([]SubdomainResult, error) {
	baseURL := p.BaseURL
	if baseURL == "" {
		baseURL = "https://rapiddns.io"
	}
	url := fmt.Sprintf("%s/subdomain/%s?full=1", baseURL, domain)
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

	matches := rapiddnsRegex.FindAllStringSubmatch(string(body), -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		host, _ := scope.NormalizeDomain(strings.TrimSpace(match[1]))
		if host == "" || (!strings.HasSuffix(host, "."+domain) && host != domain) {
			continue
		}
		if !seen[host] {
			seen[host] = true
			results = append(results, SubdomainResult{
				Subdomain: host, Source: "rapiddns", Confidence: 75,
				FirstSeen: time.Now(), Provider: "rapiddns", ProviderType: ProviderPublicNoKey,
			})
		}
	}
	return results, nil
}
