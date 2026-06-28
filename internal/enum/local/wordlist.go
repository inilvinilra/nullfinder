package local

import (
	"bufio"
	"os"
	"strings"

	"nullfinder/internal/scope"
)

// GenerateWordlistCandidates reads a wordlist file and generates candidate subdomains
// for all in-scope patterns. It validates findings against scope and RFC rules.
func GenerateWordlistCandidates(wordlistPath string, inScope []string, matcher *scope.Matcher) ([]string, error) {
	file, err := os.Open(wordlistPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" || strings.HasPrefix(word, "#") || strings.HasPrefix(word, "//") {
			continue
		}
		words = append(words, word)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	candidatesMap := make(map[string]bool)
	var candidates []string

	for _, pattern := range inScope {
		var suffix string
		if strings.HasPrefix(pattern, "*.") {
			suffix = pattern[2:]
		} else {
			suffix = pattern
		}

		for _, word := range words {
			cand := word + "." + suffix
			clean, _ := scope.NormalizeDomain(cand)
			if clean == "" {
				continue
			}

			// Ensure candidate domain is syntactically valid and matches targets
			if scope.IsValidDomain(clean) && (matcher == nil || matcher.IsInScope(clean)) {
				if !candidatesMap[clean] {
					candidatesMap[clean] = true
					candidates = append(candidates, clean)
				}
			}
		}
	}

	return candidates, nil
}
