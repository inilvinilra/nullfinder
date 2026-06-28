package scan

import (
	"nullfinder/internal/dns"
	"nullfinder/internal/portscan"
)

func BuildPortScanTargets(resolvedSubdomains []string, dnsResults []dns.ResolutionResult) []portscan.ScanTarget {
	seen := make(map[portscan.ScanTarget]struct{})
	var targets []portscan.ScanTarget

	for _, domain := range resolvedSubdomains {
		appended := false
		for _, dnsResult := range dnsResults {
			if dnsResult.Domain != domain {
				continue
			}
			for _, ip := range dnsResult.IPs {
				target := portscan.ScanTarget{Domain: domain, Address: ip}
				if _, exists := seen[target]; exists {
					continue
				}
				seen[target] = struct{}{}
				targets = append(targets, target)
				appended = true
			}
		}
		if appended {
			continue
		}

		target := portscan.ScanTarget{Domain: domain, Address: domain}
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
	}

	return targets
}
