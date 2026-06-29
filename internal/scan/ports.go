package scan

import (
	"nullfinder/internal/dns"
	"nullfinder/internal/portscan"
)

func BuildPortScanTargets(resolvedSubdomains []string, dnsResults []dns.ResolutionResult) []portscan.ScanTarget {
	seenAddress := make(map[string]struct{})
	var targets []portscan.ScanTarget

	for _, domain := range resolvedSubdomains {
		appended := false
		for _, dnsResult := range dnsResults {
			if dnsResult.Domain != domain {
				continue
			}
			for _, ip := range dnsResult.IPs {
				if _, exists := seenAddress[ip]; exists {
					appended = true
					continue
				}
				target := portscan.ScanTarget{Domain: domain, Address: ip}
				seenAddress[ip] = struct{}{}
				targets = append(targets, target)
				appended = true
			}
		}
		if appended {
			continue
		}

		target := portscan.ScanTarget{Domain: domain, Address: domain}
		if _, exists := seenAddress[target.Address]; exists {
			continue
		}
		seenAddress[target.Address] = struct{}{}
		targets = append(targets, target)
	}

	return targets
}
