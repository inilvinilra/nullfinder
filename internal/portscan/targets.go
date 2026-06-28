package portscan

import (
	"context"
	"net"
	"sort"
)

// ExpandTargets resolves hostnames into deterministic domain/address pairs.
//
// Literal IPs are kept as-is. Hostnames are expanded across all A and AAAA records,
// sorted for stable runs, and deduplicated so we do not miss ports that only exist
// behind one of several resolved addresses.
func ExpandTargets(ctx context.Context, inputs []string) []ScanTarget {
	return expandTargets(ctx, inputs, func(ctx context.Context, host string) ([]string, error) {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}

		ips := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			if addr.IP == nil {
				continue
			}
			ips = append(ips, addr.IP.String())
		}
		return ips, nil
	})
}

func expandTargets(ctx context.Context, inputs []string, lookup func(context.Context, string) ([]string, error)) []ScanTarget {
	seen := make(map[ScanTarget]struct{})
	var targets []ScanTarget
	resolutionCache := make(map[string][]string)

	appendTarget := func(domain string, address string) {
		if domain == "" {
			domain = address
		}
		target := ScanTarget{Domain: domain, Address: address}
		if _, exists := seen[target]; exists {
			return
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
	}

	for _, input := range inputs {
		if ip := net.ParseIP(input); ip != nil {
			appendTarget(input, input)
			continue
		}

		ips, ok := resolutionCache[input]
		if !ok {
			resolved, err := lookup(ctx, input)
			if err != nil {
				resolutionCache[input] = nil
			} else {
				seenIPs := make(map[string]struct{})
				for _, ip := range resolved {
					parsed := net.ParseIP(ip)
					if parsed == nil {
						continue
					}
					ip = parsed.String()
					if _, exists := seenIPs[ip]; exists {
						continue
					}
					seenIPs[ip] = struct{}{}
					ips = append(ips, ip)
				}
				sort.Strings(ips)
				resolutionCache[input] = ips
			}
		}

		if len(ips) == 0 {
			appendTarget(input, input)
			continue
		}

		for _, ip := range ips {
			appendTarget(input, ip)
		}
	}

	return targets
}
