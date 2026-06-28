package scope

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strings"
)

// JSONScope represents a structured scope configuration file in JSON format.
type JSONScope struct {
	InScope    []string `json:"in_scope"`
	OutOfScope []string `json:"out_of_scope"`
}

// ParseScopeFile parses a scope file (automatically handling JSON or plain-text line-by-line format).
func ParseScopeFile(filePath string) (inScope []string, outOfScope []string, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	if strings.HasSuffix(strings.ToLower(filePath), ".json") {
		return parseJSONScope(file)
	}

	return parseTXTReader(file)
}

func parseJSONScope(r io.Reader) (inScope []string, outOfScope []string, err error) {
	var js JSONScope
	if err := json.NewDecoder(r).Decode(&js); err != nil {
		return nil, nil, err
	}
	return js.InScope, js.OutOfScope, nil
}

func parseTXTReader(r io.Reader) (inScope []string, outOfScope []string, err error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comment lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Handle exclusions with "!" or "-" prefixes
		if strings.HasPrefix(line, "!") {
			exclusion := strings.TrimSpace(strings.TrimPrefix(line, "!"))
			if exclusion != "" {
				outOfScope = append(outOfScope, exclusion)
			}
		} else if strings.HasPrefix(line, "-") {
			exclusion := strings.TrimSpace(strings.TrimPrefix(line, "-"))
			if exclusion != "" {
				outOfScope = append(outOfScope, exclusion)
			}
		} else {
			inScope = append(inScope, line)
		}
	}
	return inScope, outOfScope, scanner.Err()
}

// ParseRawTarget takes a single raw string target, parses it, normalizes it, and matches it against the scope.
func ParseRawTarget(raw string, matcher *Matcher, source string) *Target {
	domain, root := NormalizeDomain(raw)
	if domain == "" {
		return nil
	}

	inScope := false
	if matcher != nil {
		inScope = matcher.IsInScope(domain)
	}

	return &Target{
		Raw:        raw,
		Domain:     domain,
		RootDomain: root,
		InScope:    inScope,
		Source:     source,
	}
}
