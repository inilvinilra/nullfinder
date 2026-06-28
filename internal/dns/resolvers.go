package dns

import "strings"

var defaultPublicResolvers = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}

// EffectiveResolvers resolves CLI/config resolver settings into the final resolver list.
// Returning nil means the system resolver should be used.
func EffectiveResolvers(mode string, configured []string, overrides []string, fallbackPublic bool) []string {
	mode = strings.ToLower(strings.TrimSpace(mode))

	switch mode {
	case "system":
		return nil
	case "custom":
		if len(overrides) > 0 {
			return overrides
		}
		if len(configured) > 0 {
			return configured
		}
		if fallbackPublic {
			return append([]string(nil), defaultPublicResolvers...)
		}
		return nil
	case "mixed", "":
		if len(overrides) > 0 {
			return overrides
		}
		if len(configured) > 0 {
			return configured
		}
		if fallbackPublic {
			return append([]string(nil), defaultPublicResolvers...)
		}
		return nil
	default:
		if len(overrides) > 0 {
			return overrides
		}
		if len(configured) > 0 {
			return configured
		}
		if fallbackPublic {
			return append([]string(nil), defaultPublicResolvers...)
		}
		return nil
	}
}
