package scope

import (
	"regexp"
	"strings"
)

// domainRegex validates characters allowed in domain patterns (including wildcards).
var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\*]+$`)

// IsValidDomain checks if a domain string conforms to basic structural rules.
func IsValidDomain(domain string) bool {
	domain = strings.TrimSpace(domain)
	if domain == "" || len(domain) > 255 {
		return false
	}

	if !domainRegex.MatchString(domain) {
		return false
	}

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		// Basic RFC rules for hyphens
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}

	return true
}

// ValidateTarget verifies if a parsed target is syntactically valid and in scope.
func ValidateTarget(t *Target) bool {
	if t == nil {
		return false
	}
	return IsValidDomain(t.Domain) && t.InScope
}
