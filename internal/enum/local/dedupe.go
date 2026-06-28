package local

import (
	"nullfinder/internal/enum"
	"nullfinder/internal/enum/passive"
	"nullfinder/internal/scope"
)

// DeduplicateAndFilter merges raw subdomain results, filters them against the target scope,
// aggregates duplicate records while maintaining source metadata, and computes composite confidence.
func DeduplicateAndFilter(results []passive.SubdomainResult, matcher *scope.Matcher) []enum.Asset {
	assetMap := make(map[string]*enum.Asset)

	for _, res := range results {
		domain, _ := scope.NormalizeDomain(res.Subdomain)
		if domain == "" {
			continue
		}

		// Enforce strict scope matching before doing anything else
		if matcher != nil && !matcher.IsInScope(domain) {
			continue
		}

		source := enum.AssetSource{
			Provider: res.Provider,
			Type:     string(res.ProviderType),
			SeenAt:   res.FirstSeen,
		}

		if existing, exists := assetMap[domain]; exists {
			// Ensure we do not add duplicate sources from the same provider
			alreadyPresent := false
			for _, src := range existing.Sources {
				if src.Provider == source.Provider {
					alreadyPresent = true
					break
				}
			}
			if !alreadyPresent {
				existing.Sources = append(existing.Sources, source)
			}
		} else {
			assetMap[domain] = &enum.Asset{
				Subdomain: domain,
				Sources:   []enum.AssetSource{source},
			}
		}
	}

	var deduplicated []enum.Asset
	for _, asset := range assetMap {
		maxConf := 0
		for _, src := range asset.Sources {
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
			case "wordlist":
				conf = 70
			case "permutation":
				conf = 60
			}
			if conf > maxConf {
				maxConf = conf
			}
		}

		confidence := maxConf
		// Multi-source discovery bonus (+10)
		if len(asset.Sources) > 1 {
			confidence += 10
		}

		asset.Confidence = confidence
		deduplicated = append(deduplicated, *asset)
	}

	return deduplicated
}
