package passive

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"nullfinder/internal/config"
	"nullfinder/internal/logx"
)

// Registry lists all compiled passive providers. Individual provider modules append themselves here in init().
var Registry []PassiveProvider

// GetEnabledProviders filters and returns providers enabled in the config.
func GetEnabledProviders(cfg *config.Config) []PassiveProvider {
	var enabled []PassiveProvider
	for _, p := range Registry {
		if p.Enabled(cfg) {
			enabled = append(enabled, p)
		}
	}
	return enabled
}

// EnumerateAll runs all enabled passive providers concurrently, collecting their results.
// It handles timeouts and handles individual provider errors gracefully.
func EnumerateAll(ctx context.Context, domain string, cfg *config.Config) []SubdomainResult {
	enabled := GetEnabledProviders(cfg)
	if len(enabled) == 0 {
		logx.Log.Info().Msg("No passive providers are enabled")
		return nil
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var allResults []SubdomainResult

	for _, prov := range enabled {
		wg.Add(1)
		go func(p PassiveProvider) {
			defer wg.Done()

			logx.Log.Info().Str("provider", p.Name()).Msg("Querying passive provider...")

			pCtx, cancel := context.WithTimeout(ctx, providerTimeout(cfg, p.Name()))
			defer cancel()

			res, err := enumerateWithRetry(pCtx, p, domain)
			if err != nil {
				logx.Log.Warn().
					Err(err).
					Str("provider", p.Name()).
					Msg("Passive provider execution failed")
				return
			}

			mu.Lock()
			allResults = append(allResults, res...)
			mu.Unlock()

			logx.Log.Debug().
				Str("provider", p.Name()).
				Int("found_count", len(res)).
				Msg("Passive provider finished processing")
		}(prov)
	}

	wg.Wait()
	return allResults
}

func enumerateWithRetry(ctx context.Context, p PassiveProvider, domain string) ([]SubdomainResult, error) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		res, err := p.Enumerate(ctx, domain)
		if err == nil {
			return res, nil
		}
		lastErr = err
		if !isRetryableProviderError(err) || attempt == 3 {
			break
		}

		backoff := time.Duration(attempt) * 500 * time.Millisecond
		logx.Log.Debug().
			Str("provider", p.Name()).
			Int("attempt", attempt).
			Dur("backoff", backoff).
			Err(err).
			Msg("Retrying passive provider after transient error")

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}

	return nil, lastErr
}

func isRetryableProviderError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	msg := strings.ToLower(err.Error())
	for _, token := range []string{
		"timeout",
		"temporary",
		"too many requests",
		"status 429",
		"http error: 429",
		"http error code: 429",
		"http error: 500",
		"http error code: 500",
		"http error: 502",
		"http error code: 502",
		"http error: 503",
		"http error code: 503",
		"http error: 504",
		"http error code: 504",
	} {
		if strings.Contains(msg, token) {
			return true
		}
	}

	return false
}

func providerTimeout(cfg *config.Config, providerName string) time.Duration {
	timeout := 20 * time.Second
	switch providerName {
	case "crtsh":
		if cfg.Providers.Crtsh.TimeoutSeconds > 0 {
			timeout = time.Duration(cfg.Providers.Crtsh.TimeoutSeconds) * time.Second
		}
	case "webarchive":
		if cfg.Providers.WebArchive.TimeoutSeconds > 0 {
			timeout = time.Duration(cfg.Providers.WebArchive.TimeoutSeconds) * time.Second
		}
	case "securitytrails":
		if cfg.Providers.SecurityTrails.TimeoutSeconds > 0 {
			timeout = time.Duration(cfg.Providers.SecurityTrails.TimeoutSeconds) * time.Second
		}
	case "censys":
		if cfg.Providers.Censys.TimeoutSeconds > 0 {
			timeout = time.Duration(cfg.Providers.Censys.TimeoutSeconds) * time.Second
		}
	case "shodan":
		if cfg.Providers.Shodan.TimeoutSeconds > 0 {
			timeout = time.Duration(cfg.Providers.Shodan.TimeoutSeconds) * time.Second
		}
	case "hackertarget":
		if cfg.Providers.HackerTarget.TimeoutSeconds > 0 {
			timeout = time.Duration(cfg.Providers.HackerTarget.TimeoutSeconds) * time.Second
		}
	case "anubis":
		if cfg.Providers.Anubis.TimeoutSeconds > 0 {
			timeout = time.Duration(cfg.Providers.Anubis.TimeoutSeconds) * time.Second
		}
	case "alienvault":
		if cfg.Providers.AlienVault.TimeoutSeconds > 0 {
			timeout = time.Duration(cfg.Providers.AlienVault.TimeoutSeconds) * time.Second
		}
	case "threatcrowd":
		if cfg.Providers.ThreatCrowd.TimeoutSeconds > 0 {
			timeout = time.Duration(cfg.Providers.ThreatCrowd.TimeoutSeconds) * time.Second
		}
	case "certspotter":
		if cfg.Providers.CertSpotter.TimeoutSeconds > 0 {
			timeout = time.Duration(cfg.Providers.CertSpotter.TimeoutSeconds) * time.Second
		}
	case "urlscan":
		if cfg.Providers.URLScan.TimeoutSeconds > 0 {
			timeout = time.Duration(cfg.Providers.URLScan.TimeoutSeconds) * time.Second
		}
	case "commoncrawl":
		if cfg.Providers.CommonCrawl.TimeoutSeconds > 0 {
			timeout = time.Duration(cfg.Providers.CommonCrawl.TimeoutSeconds) * time.Second
		}
	case "rapiddns":
		if cfg.Providers.RapidDNS.TimeoutSeconds > 0 {
			timeout = time.Duration(cfg.Providers.RapidDNS.TimeoutSeconds) * time.Second
		}
	case "thc":
		if cfg.Providers.THC.TimeoutSeconds > 0 {
			timeout = time.Duration(cfg.Providers.THC.TimeoutSeconds) * time.Second
		}
	}
	return timeout
}
