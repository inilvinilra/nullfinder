package scope

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// NormalizeDomain cleans up an input target string (URL, wildcard, domain name)
// and returns a clean lowercase domain/host, and the root domain if applicable.
func NormalizeDomain(raw string) (domain string, rootDomain string) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return "", ""
	}

	// Trim protocol prefix if present
	if strings.HasPrefix(raw, "http://") {
		raw = raw[7:]
	} else if strings.HasPrefix(raw, "https://") {
		raw = raw[8:]
	}

	// Remove path, query, and fragment characters
	if idx := strings.IndexAny(raw, "/?#"); idx != -1 {
		raw = raw[:idx]
	}

	// Remove port if present (check last index of colon, and ensure it isn't an IPv6 host unless outside brackets)
	if idx := strings.LastIndex(raw, ":"); idx != -1 {
		bracketIdx := strings.LastIndex(raw, "]")
		if bracketIdx == -1 || idx > bracketIdx {
			raw = raw[:idx]
		}
	}

	// Trim brackets if it was a raw IPv6 address
	raw = strings.Trim(raw, "[]")

	// Normalize wildcard representation by removing leading '*.'
	domain = strings.TrimPrefix(raw, "*.")
	domain = strings.Trim(domain, ".")

	// Extract TLD+1 root domain
	var err error
	rootDomain, err = publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		// Fallback to domain itself if public suffix parsing fails (e.g. localhost, local domains, or raw IPs)
		rootDomain = domain
	}

	return domain, rootDomain
}
