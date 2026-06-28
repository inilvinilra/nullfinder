package dns

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"
)

// WildcardDetector maintains records of domains utilizing wildcard DNS mappings.
type WildcardDetector struct {
	resolver    DNSResolver
	wildcardIPs map[string][]string
	mu          sync.RWMutex
}

// NewWildcardDetector initializes a detector.
func NewWildcardDetector(resolver DNSResolver) *WildcardDetector {
	return &WildcardDetector{
		resolver:    resolver,
		wildcardIPs: make(map[string][]string),
	}
}

func randString(n int) string {
	// Initialize local random generator to avoid seed overlap
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[r.Intn(len(letters))]
	}
	return string(b)
}

// Detect queries three randomized subdomains on the target domain.
// If all three resolve, it marks the domain as wildcard-configured and registers the IP footprint.
func (wd *WildcardDetector) Detect(ctx context.Context, domain string) bool {
	domain = strings.TrimPrefix(domain, "*.")

	randSub1 := fmt.Sprintf("nullfinder-rand-%s.%s", randString(10), domain)
	randSub2 := fmt.Sprintf("nullfinder-rand-%s.%s", randString(10), domain)
	randSub3 := fmt.Sprintf("nullfinder-rand-%s.%s", randString(10), domain)

	r1 := wd.resolver.ResolveSingle(ctx, randSub1)
	r2 := wd.resolver.ResolveSingle(ctx, randSub2)
	r3 := wd.resolver.ResolveSingle(ctx, randSub3)

	if r1.Resolved && r2.Resolved && r3.Resolved {
		ipMap := make(map[string]bool)
		for _, ip := range r1.IPs {
			ipMap[ip] = true
		}
		for _, ip := range r2.IPs {
			ipMap[ip] = true
		}
		for _, ip := range r3.IPs {
			ipMap[ip] = true
		}

		var uniqueIPs []string
		for ip := range ipMap {
			uniqueIPs = append(uniqueIPs, ip)
		}

		wd.mu.Lock()
		wd.wildcardIPs[domain] = uniqueIPs
		wd.mu.Unlock()

		return true
	}

	return false
}

// IsWildcardIP checks if any target IPs belong to the wildcard IP sets of the domain or its parent roots.
func (wd *WildcardDetector) IsWildcardIP(domain string, ips []string) bool {
	wd.mu.RLock()
	defer wd.mu.RUnlock()

	for parent, wildcardIPList := range wd.wildcardIPs {
		if domain == parent || strings.HasSuffix(domain, "."+parent) {
			for _, ip := range ips {
				for _, wIP := range wildcardIPList {
					if ip == wIP {
						return true
					}
				}
			}
		}
	}

	return false
}
