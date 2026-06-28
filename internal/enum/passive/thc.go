package passive

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"nullfinder/internal/config"
	"nullfinder/internal/scope"
)

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func stripANSI(str string) string {
	return ansiRegex.ReplaceAllString(str, "")
}

// THCProvider queries the ip.thc.org subdomain API database.
type THCProvider struct {
	BaseURL string
}

func init() {
	Registry = append(Registry, &THCProvider{})
}

func (p *THCProvider) Name() string                    { return "thc" }
func (p *THCProvider) Type() ProviderType              { return ProviderPublicNoKey }
func (p *THCProvider) RequiresAPIKey() bool            { return false }
func (p *THCProvider) Enabled(cfg *config.Config) bool { return cfg.Providers.THC.Enabled }

func (p *THCProvider) Enumerate(ctx context.Context, domain string) ([]SubdomainResult, error) {
	baseURL := p.BaseURL
	if baseURL == "" {
		baseURL = "https://ip.thc.org"
	}

	seen := make(map[string]bool)
	var results []SubdomainResult

	// Start with initial page, ask for no color
	currentURL := fmt.Sprintf("%s/sb/%s?nocolor=1", baseURL, domain)
	page := 1
	maxPages := 10 // Safety limit to prevent rate limits / timeouts

	for currentURL != "" && page <= maxPages {
		// Respect rate limit / context cancellation check
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", currentURL, nil)
		if err != nil {
			return results, err
		}
		req.Header.Set("User-Agent", "NullFinder/1.0")

		resp, err := HTTPClient.Do(req)
		if err != nil {
			return results, err
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return results, fmt.Errorf("thc api error status: %d", resp.StatusCode)
		}

		var nextURL string
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			// Clean line of any ANSI escape sequences
			line = stripANSI(line)

			// Parse next page indicator
			// Example: ;;Next Page: https://ip.thc.org/example.com?p=00085406313232313639f07fffff9bf07fffff9b
			if strings.HasPrefix(line, ";;Next Page:") {
				nextParts := strings.SplitN(line, ";;Next Page:", 2)
				if len(nextParts) == 2 {
					nextLink := strings.TrimSpace(nextParts[1])
					// Make sure to append nocolor parameter to next page
					if !strings.Contains(nextLink, "nocolor=") {
						if strings.Contains(nextLink, "?") {
							nextLink += "&nocolor=1"
						} else {
							nextLink += "?nocolor=1"
						}
					}
					nextURL = nextLink
				}
				continue
			}

			// Ignore other comments
			if strings.HasPrefix(line, ";") {
				continue
			}

			// Clean and validate subdomain
			host, _ := scope.NormalizeDomain(line)
			if host == "" || (!strings.HasSuffix(host, "."+domain) && host != domain) {
				continue
			}

			if !seen[host] {
				seen[host] = true
				results = append(results, SubdomainResult{
					Subdomain:    host,
					Source:       "thc",
					Confidence:   85,
					FirstSeen:    time.Now(),
					Provider:     "thc",
					ProviderType: ProviderPublicNoKey,
				})
			}
		}

		resp.Body.Close()

		if err := scanner.Err(); err != nil {
			return results, err
		}

		currentURL = nextURL
		page++

		// Small delay to prevent hitting rate limits too aggressively
		if currentURL != "" && page <= maxPages {
			select {
			case <-ctx.Done():
				return results, ctx.Err()
			case <-time.After(1500 * time.Millisecond):
			}
		}
	}

	return results, nil
}
