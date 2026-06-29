package dns

import (
	"context"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

// ResolutionResult stores the resolved host information.
type ResolutionResult struct {
	Domain   string   `json:"domain"`
	IPs      []string `json:"ips"`
	CNAME    string   `json:"cname,omitempty"`
	NS       []string `json:"ns,omitempty"`
	MX       []string `json:"mx,omitempty"`
	Resolved bool     `json:"resolved"`
	Error    error    `json:"-"`
}

// DNSResolver defines the interface for executing DNS queries.
type DNSResolver interface {
	ResolveSingle(ctx context.Context, domain string) ResolutionResult
	ResolveBatch(ctx context.Context, domains []string) []ResolutionResult
}

// Resolver manages native DNS resolution tasks.

type Resolver struct {
	resolvers []string
	useSystem bool
	threads   int
	rateLimit int
	timeout   time.Duration
}

// NewResolver initializes a Resolver configured with worker pools and query constraints.
func NewResolver(resolvers []string, threads int, rateLimit int, timeoutSeconds int) *Resolver {
	if threads <= 0 {
		threads = 10
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 5
	}
	return &Resolver{
		resolvers: resolvers,
		useSystem: len(resolvers) == 0,
		threads:   threads,
		rateLimit: rateLimit,
		timeout:   time.Duration(timeoutSeconds) * time.Second,
	}
}

func (r *Resolver) getNativeResolver() *net.Resolver {
	if r.useSystem {
		return net.DefaultResolver
	}

	// Select a resolver IP randomly to balance load
	ip := r.resolvers[rand.Intn(len(r.resolvers))]
	if !strings.Contains(ip, ":") {
		ip = ip + ":53"
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: r.timeout,
			}
			return d.DialContext(ctx, "udp", ip)
		},
	}
}

// ResolveSingle runs lookups for A, AAAA, and CNAME records on a single target domain.
func (r *Resolver) ResolveSingle(ctx context.Context, domain string) ResolutionResult {
	res := ResolutionResult{Domain: domain}
	nativeResolver := r.getNativeResolver()

	// 1. Fetch CNAME records (if any)
	cname, err := nativeResolver.LookupCNAME(ctx, domain)
	if err == nil {
		cnameClean := strings.TrimSuffix(cname, ".")
		// Only set CNAME if it's not equal to the domain itself (Go resolver returns the domain if no CNAME exists)
		if cnameClean != domain {
			res.CNAME = cnameClean
		}
	}

	// 2. Fetch IP addresses (LookupHost queries both A and AAAA)
	ips, err := nativeResolver.LookupHost(ctx, domain)
	if err != nil {
		res.Error = err
	} else if len(ips) > 0 {
		res.IPs = ips
		res.Resolved = true
	}

	// 3. Fetch NS records for root and delegated zones.
	if nsRecords, err := nativeResolver.LookupNS(ctx, domain); err == nil {
		for _, nsRecord := range nsRecords {
			host := strings.TrimSuffix(nsRecord.Host, ".")
			if host != "" {
				res.NS = append(res.NS, host)
			}
		}
	}

	// 4. Fetch MX records to discover mail infrastructure names.
	if mxRecords, err := nativeResolver.LookupMX(ctx, domain); err == nil {
		for _, mxRecord := range mxRecords {
			host := strings.TrimSuffix(mxRecord.Host, ".")
			if host != "" {
				res.MX = append(res.MX, host)
			}
		}
	}

	return res
}

// ResolveBatch runs resolutions across multiple domains concurrently, respecting worker thread limits and rate limits.
func (r *Resolver) ResolveBatch(ctx context.Context, domains []string) []ResolutionResult {
	var wg sync.WaitGroup
	results := make([]ResolutionResult, len(domains))
	sem := make(chan struct{}, r.threads)

	var ticker *time.Ticker
	if r.rateLimit > 0 {
		interval := time.Second / time.Duration(r.rateLimit)
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	for i, domain := range domains {
		select {
		case <-ctx.Done():
			wg.Wait()
			return results
		default:
		}

		if ticker != nil {
			<-ticker.C
		}

		sem <- struct{}{}
		wg.Add(1)

		go func(idx int, dom string) {
			defer func() {
				<-sem
				wg.Done()
			}()

			results[idx] = r.ResolveSingle(ctx, dom)
		}(i, domain)
	}

	wg.Wait()
	return results
}
