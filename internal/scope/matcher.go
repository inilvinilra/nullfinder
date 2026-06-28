package scope

import (
	"strings"
)

// MatchDomain checks if a domain is matched by a pattern (which can be a wildcard).
func MatchDomain(domain, pattern string) bool {
	domain = strings.TrimSpace(strings.ToLower(domain))
	pattern = strings.TrimSpace(strings.ToLower(pattern))

	if domain == "" || pattern == "" {
		return false
	}

	// Handle wildcards starting with "*."
	isWildcard := strings.HasPrefix(pattern, "*.")
	basePattern := pattern
	if isWildcard {
		basePattern = pattern[2:]
	}

	// Exact match
	if domain == basePattern {
		return true
	}

	// Wildcard suffix match (e.g., api.example.com matches *.example.com)
	if isWildcard {
		return strings.HasSuffix(domain, "."+basePattern)
	}

	return false
}

// Matcher holds the configuration for in-scope and out-of-scope patterns.
type Matcher struct {
	InScope    []string
	OutOfScope []string
}

// NewMatcher initializes a new Matcher instance.
func NewMatcher(inScope, outOfScope []string) *Matcher {
	m := &Matcher{
		InScope:    make([]string, 0, len(inScope)),
		OutOfScope: make([]string, 0, len(outOfScope)),
	}

	for _, p := range inScope {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			m.InScope = append(m.InScope, p)
		}
	}

	for _, p := range outOfScope {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			m.OutOfScope = append(m.OutOfScope, p)
		}
	}

	return m
}

// IsInScope checks if a given domain is within the allowed targets.
// Exclusions (OutOfScope) always take precedence over inclusions (InScope).
func (m *Matcher) IsInScope(domain string) bool {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return false
	}

	// Exclusions override inclusions
	for _, p := range m.OutOfScope {
		if MatchDomain(domain, p) {
			return false
		}
	}

	// Check if matches in-scope patterns
	for _, p := range m.InScope {
		if MatchDomain(domain, p) {
			return true
		}
	}

	return false
}
