package passive

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"nullfinder/internal/config"
	"nullfinder/internal/logx"
)

// Registry lists all compiled passive providers. Individual provider modules append themselves here in init().
var Registry []PassiveProvider

var providerRuntimeState sync.Map

type runtimeProviderState struct {
	Failures          int
	CooldownUntil     time.Time
	Disabled          bool
	DisableReason     string
	DisableAnnounced  bool
	CooldownAnnounced bool
}

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

			if reason, ok := providerDisabledReason(p.Name()); ok {
				logProviderDisabledOnce(p.Name(), reason)
				return
			}
			if until, ok := providerCooldownUntil(p.Name()); ok {
				logProviderCooldownOnce(p.Name(), until)
				return
			}

			logx.Log.Debug().Str("provider", p.Name()).Msg("Querying passive provider")

			pCtx, cancel := context.WithTimeout(ctx, providerTimeout(cfg, p.Name()))
			defer cancel()

			res, err := enumerateWithRetry(pCtx, p, domain)
			if err != nil {
				recordProviderFailure(p.Name(), err)
				logProviderFailure(p.Name(), err)
				return
			}
			recordProviderSuccess(p.Name())

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
		"eof",
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

func providerCooldownUntil(name string) (time.Time, bool) {
	value, ok := providerRuntimeState.Load(name)
	if !ok {
		return time.Time{}, false
	}
	state, ok := value.(runtimeProviderState)
	if !ok || state.CooldownUntil.IsZero() {
		return time.Time{}, false
	}
	if time.Now().Before(state.CooldownUntil) {
		return state.CooldownUntil, true
	}
	state.CooldownUntil = time.Time{}
	state.CooldownAnnounced = false
	providerRuntimeState.Store(name, state)
	return time.Time{}, false
}

func recordProviderSuccess(name string) {
	providerRuntimeState.Store(name, runtimeProviderState{})
}

func recordProviderFailure(name string, err error) {
	value, _ := providerRuntimeState.Load(name)
	state, _ := value.(runtimeProviderState)
	state.Failures++
	if shouldDisableProvider(err, state.Failures) {
		state.Disabled = true
		state.DisableReason = summarizeProviderError(err)
		state.CooldownUntil = time.Time{}
		state.CooldownAnnounced = false
		if !state.DisableAnnounced {
			logx.Log.Info().
				Str("provider", name).
				Str("reason", state.DisableReason).
				Msg("Passive provider disabled for this run")
			state.DisableAnnounced = true
		}
		providerRuntimeState.Store(name, state)
		return
	}
	if cooldown := providerFailureCooldown(err, state.Failures); cooldown > 0 {
		state.CooldownUntil = time.Now().Add(cooldown)
		state.CooldownAnnounced = false
		logx.Log.Debug().
			Str("provider", name).
			Str("cooldown", cooldown.String()).
			Str("reason", summarizeProviderError(err)).
			Msg("Passive provider cooled down after repeated failures")
	}
	providerRuntimeState.Store(name, state)
}

func providerFailureCooldown(err error, failures int) time.Duration {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "429"), strings.Contains(message, "too many requests"):
		if failures >= 1 {
			return 2 * time.Minute
		}
	case strings.Contains(message, "context deadline exceeded"), strings.Contains(message, "timeout"):
		if failures >= 2 {
			return 45 * time.Second
		}
	case strings.Contains(message, "eof"), strings.Contains(message, "connect: connection refused"):
		if failures >= 2 {
			return 30 * time.Second
		}
	case strings.Contains(message, "502"), strings.Contains(message, "503"), strings.Contains(message, "504"):
		if failures >= 2 {
			return 30 * time.Second
		}
	}
	return 0
}

func shouldDisableProvider(err error, failures int) bool {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "429"), strings.Contains(message, "too many requests"):
		return true
	case strings.Contains(message, "context deadline exceeded"), strings.Contains(message, "timeout"):
		return failures >= 4
	case strings.Contains(message, "connect: connection refused"), strings.Contains(message, "tls handshake timeout"):
		return failures >= 3
	case strings.Contains(message, "502"), strings.Contains(message, "503"), strings.Contains(message, "504"), strings.Contains(message, "eof"):
		return failures >= 3
	}
	return false
}

func providerDisabledReason(name string) (string, bool) {
	value, ok := providerRuntimeState.Load(name)
	if !ok {
		return "", false
	}
	state, ok := value.(runtimeProviderState)
	if !ok || !state.Disabled {
		return "", false
	}
	return state.DisableReason, true
}

func logProviderDisabledOnce(name, reason string) {
	value, _ := providerRuntimeState.Load(name)
	state, _ := value.(runtimeProviderState)
	if state.DisableAnnounced {
		return
	}
	logx.Log.Info().
		Str("provider", name).
		Str("reason", reason).
		Msg("Passive provider remains disabled for this run")
	state.DisableAnnounced = true
	providerRuntimeState.Store(name, state)
}

func logProviderCooldownOnce(name string, until time.Time) {
	value, _ := providerRuntimeState.Load(name)
	state, _ := value.(runtimeProviderState)
	if state.CooldownAnnounced {
		return
	}
	logx.Log.Debug().
		Str("provider", name).
		Time("retry_after", until).
		Msg("Passive provider skipped during cooldown window")
	state.CooldownAnnounced = true
	providerRuntimeState.Store(name, state)
}

func logProviderFailure(name string, err error) {
	logx.Log.Debug().
		Str("provider", name).
		Str("reason", summarizeProviderError(err)).
		Msg("Passive provider unavailable, continuing")
}

func summarizeProviderError(err error) string {
	message := strings.TrimSpace(err.Error())
	if idx := strings.IndexByte(message, '\n'); idx >= 0 {
		message = message[:idx]
	}
	if len(message) > 120 {
		message = message[:117] + "..."
	}
	return fmt.Sprintf("%s", message)
}
