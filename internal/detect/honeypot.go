package detect

import (
	"fmt"
	"sort"
	"strings"
)

type indicator struct {
	needle string
	label  string
	score  int
}

var honeypotIndicators = []indicator{
	{needle: "cowrie", label: "Cowrie", score: 100},
	{needle: "kippo", label: "Kippo", score: 100},
	{needle: "dionaea", label: "Dionaea", score: 100},
	{needle: "honeyd", label: "Honeyd", score: 100},
	{needle: "glastopf", label: "Glastopf", score: 100},
	{needle: "conpot", label: "Conpot", score: 100},
	{needle: "opencanary", label: "OpenCanary", score: 100},
	{needle: "canarytokens", label: "Canarytokens", score: 100},
	{needle: "honeytrap", label: "Honeytrap", score: 100},
	{needle: "heralding", label: "Heralding", score: 100},
	{needle: "t-pot", label: "T-Pot", score: 100},
	{needle: "honeypot", label: "Honeypot", score: 100},
}

// DetectPotentialHoneypot applies strict, high-confidence heuristics to detect honeypot-like services.
func DetectPotentialHoneypot(parts ...string) (bool, string) {
	var matched []string
	score := 0

	for _, part := range parts {
		if part == "" {
			continue
		}
		lower := strings.ToLower(part)
		for _, hint := range honeypotIndicators {
			if strings.Contains(lower, hint.needle) {
				score += hint.score
				matched = append(matched, hint.label)
			}
		}
	}

	if len(matched) == 0 {
		return false, ""
	}

	// Keep the signal stable and explainable.
	matched = uniqueStrings(matched)
	sort.Strings(matched)

	if score < 100 && len(matched) < 2 {
		return false, ""
	}

	return true, fmt.Sprintf("honeypot indicators: %s", strings.Join(matched, ", "))
}

// DetectPotentialHoneypotWithContext adds lightweight anomaly checks using the service port.
func DetectPotentialHoneypotWithContext(port int, service string, parts ...string) (bool, string) {
	if ok, reason := DetectPotentialHoneypot(parts...); ok {
		return true, reason
	}

	lowerService := strings.ToLower(service)
	for _, part := range parts {
		lower := strings.ToLower(part)
		if lower == "" {
			continue
		}

		if isWebPort(port) && (strings.Contains(lower, "ssh-") || strings.Contains(lower, "openssh")) {
			return true, fmt.Sprintf("web port %d returned SSH-style banner", port)
		}
		if isSSHPort(port) && (strings.Contains(lower, "http/") || strings.Contains(lower, "<html") || strings.Contains(lower, "server:")) {
			return true, fmt.Sprintf("ssh port %d returned HTTP-style content", port)
		}
		if lowerService == "unknown" && (strings.Contains(lower, "honeypot") || strings.Contains(lower, "decoy") || strings.Contains(lower, "trap")) {
			return true, "unknown service exposed honeypot markers"
		}
	}

	return false, ""
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func isWebPort(port int) bool {
	switch port {
	case 80, 443, 8080, 8443, 8000, 3000, 5000, 8888:
		return true
	}
	return false
}

func isSSHPort(port int) bool {
	switch port {
	case 22, 2222, 2200:
		return true
	}
	return false
}
