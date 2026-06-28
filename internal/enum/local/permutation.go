package local

import (
	"fmt"
	"strings"

	"nullfinder/internal/scope"
)

var defaultPermutationWords = []string{
	"dev",
	"stage",
	"prod",
	"test",
	"admin",
	"api",
	"corp",
	"internal",
	"staging",
	"qa",
	"demo",
	"app",
	"web",
	"mail",
	"auth",
	"portal",
	"vpn",
	"gateway",
	"edge",
	"cdn",
	"mx",
	"ns",
}

// GeneratePermutations takes currently discovered subdomains and applies mutation rules
// (prepending/appending, appending numbers, and separator manipulation) to produce new candidate names.
func GeneratePermutations(subdomains []string, matcher *scope.Matcher) []string {
	candidatesMap := make(map[string]bool)
	var candidates []string

	for _, sub := range subdomains {
		// Split label and suffix
		parts := strings.SplitN(sub, ".", 2)
		if len(parts) < 2 {
			continue
		}
		label := parts[0]
		suffix := parts[1]
		labelVariants := buildLabelVariants(label)

		for _, variant := range labelVariants {
			if variant == label {
				continue
			}
			clean, _ := scope.NormalizeDomain(fmt.Sprintf("%s.%s", variant, suffix))
			if clean != "" && scope.IsValidDomain(clean) && (matcher == nil || matcher.IsInScope(clean)) {
				if !candidatesMap[clean] && clean != sub {
					candidatesMap[clean] = true
					candidates = append(candidates, clean)
				}
			}
		}

		// 1. Prepend and append common words
		for _, variant := range labelVariants {
			for _, word := range defaultPermutationWords {
				c1 := fmt.Sprintf("%s-%s.%s", word, variant, suffix)
				c2 := fmt.Sprintf("%s-%s.%s", variant, word, suffix)

				for _, c := range []string{c1, c2} {
					clean, _ := scope.NormalizeDomain(c)
					if clean != "" && scope.IsValidDomain(clean) && (matcher == nil || matcher.IsInScope(clean)) {
						if !candidatesMap[clean] && clean != sub {
							candidatesMap[clean] = true
							candidates = append(candidates, clean)
						}
					}
				}
			}
		}

		// 2. Append sequential digits 1 to 9
		for _, variant := range labelVariants {
			for i := 1; i <= 9; i++ {
				c := fmt.Sprintf("%s%d.%s", variant, i, suffix)
				clean, _ := scope.NormalizeDomain(c)
				if clean != "" && scope.IsValidDomain(clean) && (matcher == nil || matcher.IsInScope(clean)) {
					if !candidatesMap[clean] && clean != sub {
						candidatesMap[clean] = true
						candidates = append(candidates, clean)
					}
				}
			}
		}

		// 3. Swap delimiters or remove separators
		if strings.Contains(label, "-") {
			// e.g., api-dev.example.com -> api.dev.example.com
			c1 := strings.ReplaceAll(label, "-", ".") + "." + suffix
			// e.g., api-dev.example.com -> apidev.example.com
			c2 := strings.ReplaceAll(label, "-", "") + "." + suffix

			for _, c := range []string{c1, c2} {
				clean, _ := scope.NormalizeDomain(c)
				if clean != "" && scope.IsValidDomain(clean) && (matcher == nil || matcher.IsInScope(clean)) {
					if !candidatesMap[clean] && clean != sub {
						candidatesMap[clean] = true
						candidates = append(candidates, clean)
					}
				}
			}
		}
	}

	return candidates
}

func buildLabelVariants(label string) []string {
	variants := []string{label}
	seen := map[string]struct{}{label: {}}

	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		variants = append(variants, value)
	}

	for _, token := range []string{"srv", "server", "websrv", "node", "host"} {
		if strings.Contains(label, token) {
			add(strings.ReplaceAll(label, token, ""))
		}
	}

	if strings.Contains(label, "-") {
		add(strings.ReplaceAll(label, "-", ""))
	}

	if idx := strings.LastIndexAny(label, "0123456789"); idx == len(label)-1 {
		trimmed := strings.TrimRight(label, "0123456789")
		add(trimmed)
	}

	return variants
}
