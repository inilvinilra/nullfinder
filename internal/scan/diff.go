package scan

import (
	"fmt"

	"nullfinder/internal/storage"
)

// CompareAssets compares previous and current assets lists to identify new findings.
func CompareAssets(prev []storage.AssetRecord, next []storage.AssetRecord) (newSubs []string, newPorts []string, newWeb []string) {
	prevMap := make(map[string]storage.AssetRecord)
	for _, a := range prev {
		prevMap[a.Domain] = a
	}

	for _, a := range next {
		old, exists := prevMap[a.Domain]
		if !exists {
			// Entirely new subdomain discovered
			newSubs = append(newSubs, a.Domain)

			// Log its details as part of new findings
			for _, p := range a.Ports {
				newPorts = append(newPorts, fmt.Sprintf("%s:%d", a.Domain, p))
			}
			for _, s := range a.Schemes {
				newWeb = append(newWeb, s)
			}
			continue
		}

		// Subdomain existed previously; check for new open TCP ports
		oldPorts := make(map[int]bool)
		for _, p := range old.Ports {
			oldPorts[p] = true
		}
		for _, p := range a.Ports {
			if !oldPorts[p] {
				newPorts = append(newPorts, fmt.Sprintf("%s:%d", a.Domain, p))
			}
		}

		// Check for new HTTP/HTTPS web endpoints
		oldSchemes := make(map[string]bool)
		for _, s := range old.Schemes {
			oldSchemes[s] = true
		}
		for _, s := range a.Schemes {
			if !oldSchemes[s] {
				newWeb = append(newWeb, s)
			}
		}
	}

	return newSubs, newPorts, newWeb
}
