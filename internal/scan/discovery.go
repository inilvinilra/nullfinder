package scan

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"nullfinder/internal/config"
	"nullfinder/internal/dns"
	"nullfinder/internal/enum"
	"nullfinder/internal/enum/local"
	"nullfinder/internal/enum/passive"
	"nullfinder/internal/logx"
	"nullfinder/internal/scope"
)

// DiscoverySettings determines which discovery stages run for a command.
type DiscoverySettings struct {
	PassiveEnabled     bool
	WordlistEnabled    bool
	PermutationEnabled bool
	MaxDepth           int
}

// DiscoveryOptions bundles shared discovery inputs used by scan and enum flows.
type DiscoveryOptions struct {
	InScope    []string
	OutOfScope []string
	Mode       string
	Wordlist   string
	Resolvers  []string
	RateLimit  int
	Settings   DiscoverySettings
}

// DiscoveryResult contains deduplicated assets and DNS validation artifacts.
type DiscoveryResult struct {
	CandidateSubdomains []string
	Assets              []enum.Asset
	AllSubdomains       []string
	ResolvedSubdomains  []string
	WildcardSubdomains  []string
	CNAMEs              []string
	DNSResults          []dns.ResolutionResult
}

// ResolveDiscoverySettings derives discovery behavior from mode, config, and explicit flags.
func ResolveDiscoverySettings(mode string, cfg *config.Config, forceActive bool, forcePassive bool, maxDepth int) DiscoverySettings {
	mode = strings.ToLower(strings.TrimSpace(mode))

	settings := DiscoverySettings{
		PassiveEnabled:     mode != "local",
		WordlistEnabled:    mode == "local" || mode == "hybrid" || mode == "full",
		PermutationEnabled: mode == "hybrid" || mode == "full",
		MaxDepth:           maxDepth,
	}

	if cfg != nil {
		if settings.MaxDepth <= 0 {
			settings.MaxDepth = cfg.Scan.MaxDepth
		}
		if !forceActive {
			settings.WordlistEnabled = settings.WordlistEnabled && cfg.Enum.LocalWordlistEnabled
			settings.PermutationEnabled = settings.PermutationEnabled && cfg.Enum.LocalPermutationEnabled
		}
	}

	if settings.MaxDepth <= 0 {
		settings.MaxDepth = 1
	}

	if forceActive && !forcePassive {
		settings.PassiveEnabled = false
		settings.WordlistEnabled = true
		settings.PermutationEnabled = true
	}

	if forcePassive && !forceActive {
		settings.PassiveEnabled = true
		settings.WordlistEnabled = false
		settings.PermutationEnabled = false
	}

	if forceActive && forcePassive {
		settings.PassiveEnabled = true
		settings.WordlistEnabled = true
		settings.PermutationEnabled = true
	}

	return settings
}

// DiscoverAssets runs passive/local discovery, wildcard filtering, and final DNS verification.
func DiscoverAssets(ctx context.Context, cfg *config.Config, opts DiscoveryOptions) (*DiscoveryResult, error) {
	matcher := scope.NewMatcher(opts.InScope, opts.OutOfScope)
	roots := uniqueRoots(opts.InScope)
	if len(roots) == 0 {
		return nil, fmt.Errorf("no valid in-scope roots were provided")
	}

	resolver := dns.NewResolver(opts.Resolvers, cfg.Scan.Threads, opts.RateLimit, cfg.DNS.TimeoutSeconds)
	detector := dns.NewWildcardDetector(resolver)

	if cfg.DNS.WildcardDetection {
		for _, root := range roots {
			if detector.Detect(ctx, root) {
				logx.Log.Warn().Str("domain", root).Msg("Wildcard DNS detected on domain")
			}
		}
	}

	assetsMap := make(map[string]*enum.Asset)
	mergeAsset := func(subdomain string, source enum.AssetSource) bool {
		subdomain, _ = scope.NormalizeDomain(subdomain)
		if subdomain == "" {
			return false
		}
		if !matcher.IsInScope(subdomain) {
			return false
		}

		if existing, exists := assetsMap[subdomain]; exists {
			for _, src := range existing.Sources {
				if src.Provider == source.Provider {
					return false
				}
			}
			existing.Sources = append(existing.Sources, source)
			return false
		}

		assetsMap[subdomain] = &enum.Asset{
			Subdomain: subdomain,
			Sources:   []enum.AssetSource{source},
		}
		return true
	}

	if opts.Settings.PassiveEnabled {
		logx.Log.Info().Int("roots", len(roots)).Msg("Running passive OSINT subdomain discovery...")
		for _, root := range roots {
			rawPassive := passive.EnumerateAll(ctx, root, cfg)
			for _, pRes := range rawPassive {
				mergeAsset(pRes.Subdomain, enum.AssetSource{
					Provider: pRes.Provider,
					Type:     string(pRes.ProviderType),
					SeenAt:   pRes.FirstSeen,
				})
			}
		}
	}

	logx.Log.Info().Int("roots", len(roots)).Msg("Collecting DNS infrastructure seeds...")
	for _, root := range roots {
		dnsRes := resolver.ResolveSingle(ctx, root)
		for _, ns := range dnsRes.NS {
			mergeAsset(ns, enum.AssetSource{
				Provider: "dns-ns",
				Type:     "dns",
				SeenAt:   time.Now(),
			})
		}
		for _, mx := range dnsRes.MX {
			mergeAsset(mx, enum.AssetSource{
				Provider: "dns-mx",
				Type:     "dns",
				SeenAt:   time.Now(),
			})
		}
		if dnsRes.CNAME != "" {
			mergeAsset(dnsRes.CNAME, enum.AssetSource{
				Provider: "dns-cname",
				Type:     "dns",
				SeenAt:   time.Now(),
			})
		}
		if len(dnsRes.MX) > 0 {
			// MX-backed domains frequently expose a mail.<root> alias even when mail is hosted externally.
			mergeAsset("mail."+root, enum.AssetSource{
				Provider: "mail-heuristic",
				Type:     "inference",
				SeenAt:   time.Now(),
			})
		}
	}

	if opts.Settings.WordlistEnabled {
		wordlistFile := opts.Wordlist
		if wordlistFile == "" {
			wordlistFile = cfg.Enum.Wordlist
		}
		if wordlistFile == "" {
			wordlistFile = "wordlists/small.txt"
		}

		if _, err := os.Stat(wordlistFile); err == nil {
			logx.Log.Info().Str("wordlist", wordlistFile).Msg("Running active wordlist subdomain brute-force...")
			candidates, err := local.GenerateWordlistCandidates(wordlistFile, opts.InScope, matcher)
			if err != nil {
				return nil, fmt.Errorf("failed to generate wordlist candidates: %w", err)
			}
			logx.Log.Info().Int("count", len(candidates)).Msg("Resolving wordlist candidates...")
			for _, dnsRes := range resolver.ResolveBatch(ctx, candidates) {
				if dnsRes.Resolved && !detector.IsWildcardIP(dnsRes.Domain, dnsRes.IPs) {
					mergeAsset(dnsRes.Domain, enum.AssetSource{
						Provider: "wordlist",
						Type:     "active",
						SeenAt:   time.Now(),
					})
				}
			}
		} else {
			logx.Log.Warn().Str("path", wordlistFile).Msg("Wordlist file not found, skipping brute-force")
		}
	}

	if opts.Settings.PermutationEnabled {
		logx.Log.Info().Int("depth", opts.Settings.MaxDepth).Msg("Running subdomain permutations generation...")

		seenCandidates := make(map[string]struct{})
		frontier := mapKeys(assetsMap)

		for depth := 0; depth < opts.Settings.MaxDepth && len(frontier) > 0; depth++ {
			candidates := local.GeneratePermutations(frontier, matcher)
			var filtered []string
			for _, candidate := range candidates {
				if _, exists := seenCandidates[candidate]; exists {
					continue
				}
				seenCandidates[candidate] = struct{}{}
				if _, exists := assetsMap[candidate]; exists {
					continue
				}
				filtered = append(filtered, candidate)
			}

			if len(filtered) == 0 {
				break
			}

			logx.Log.Info().Int("depth", depth+1).Int("count", len(filtered)).Msg("Resolving permutation candidates...")
			nextFrontier := make([]string, 0, len(filtered))
			for _, dnsRes := range resolver.ResolveBatch(ctx, filtered) {
				if dnsRes.Resolved && !detector.IsWildcardIP(dnsRes.Domain, dnsRes.IPs) {
					if mergeAsset(dnsRes.Domain, enum.AssetSource{
						Provider: "permutation",
						Type:     "active",
						SeenAt:   time.Now(),
					}) {
						nextFrontier = append(nextFrontier, dnsRes.Domain)
					}
				}
			}
			frontier = nextFrontier
		}
	}

	allSubs := mapKeys(assetsMap)
	logx.Log.Info().Int("count", len(allSubs)).Msg("Executing final DNS verification on all discovered subdomains...")
	finalDNSResults := resolver.ResolveBatch(ctx, allSubs)

	var (
		assets             []enum.Asset
		resolvedSubdomains []string
		wildcardSubdomains []string
		cnames             []string
	)

	for _, dnsRes := range finalDNSResults {
		assetPtr := assetsMap[dnsRes.Domain]
		if assetPtr == nil {
			continue
		}

		confidence := scoreAsset(assetPtr.Sources)
		if !dnsRes.Resolved {
			continue
		}
		if detector.IsWildcardIP(dnsRes.Domain, dnsRes.IPs) {
			confidence -= 30
			wildcardSubdomains = append(wildcardSubdomains, fmt.Sprintf("%s -> %s", dnsRes.Domain, strings.Join(dnsRes.IPs, ", ")))
			continue
		}

		confidence += 10
		resolvedSubdomains = append(resolvedSubdomains, dnsRes.Domain)
		if dnsRes.CNAME != "" {
			cnames = append(cnames, fmt.Sprintf("%s -> %s", dnsRes.Domain, dnsRes.CNAME))
		}
		assetPtr.Confidence = confidence
		assets = append(assets, *assetPtr)
	}

	return &DiscoveryResult{
		CandidateSubdomains: allSubs,
		Assets:              assets,
		AllSubdomains:       resolvedSubdomains,
		ResolvedSubdomains:  resolvedSubdomains,
		WildcardSubdomains:  wildcardSubdomains,
		CNAMEs:              cnames,
		DNSResults:          finalDNSResults,
	}, nil
}

func uniqueRoots(inScope []string) []string {
	seen := make(map[string]struct{})
	var roots []string
	for _, pattern := range inScope {
		_, root := scope.NormalizeDomain(pattern)
		if root == "" {
			continue
		}
		if _, exists := seen[root]; exists {
			continue
		}
		seen[root] = struct{}{}
		roots = append(roots, root)
	}
	return roots
}

func mapKeys(assets map[string]*enum.Asset) []string {
	keys := make([]string, 0, len(assets))
	for key := range assets {
		keys = append(keys, key)
	}
	return keys
}

func scoreAsset(sources []enum.AssetSource) int {
	maxConf := 0
	for _, src := range sources {
		conf := 0
		switch src.Provider {
		case "crtsh":
			conf = 85
		case "webarchive":
			conf = 75
		case "securitytrails":
			conf = 95
		case "censys":
			conf = 90
		case "shodan":
			conf = 85
		case "hackertarget":
			conf = 80
		case "anubis":
			conf = 75
		case "alienvault":
			conf = 80
		case "threatcrowd":
			conf = 70
		case "certspotter":
			conf = 80
		case "urlscan":
			conf = 75
		case "commoncrawl":
			conf = 70
		case "rapiddns":
			conf = 72
		case "thc":
			conf = 72
		case "wordlist":
			conf = 70
		case "permutation":
			conf = 60
		case "mail-heuristic":
			conf = 55
		}
		if conf > maxConf {
			maxConf = conf
		}
	}
	if len(sources) > 1 {
		maxConf += 10
	}
	return maxConf
}
