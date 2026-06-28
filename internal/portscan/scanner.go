package portscan

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nullfinder/internal/detect"
)

// PortResult represents an audit finding of a targeted port.
type PortResult struct {
	Domain            string `json:"domain,omitempty"`
	Address           string `json:"address,omitempty"`
	IP                string `json:"ip"`
	Port              int    `json:"port"`
	State             string `json:"state"` // "open", "closed", or "filtered"
	Reason            string `json:"reason,omitempty"`
	Service           string `json:"service"`
	Product           string `json:"product,omitempty"`
	Version           string `json:"version,omitempty"`
	Banner            string `json:"banner,omitempty"`
	PotentialHoneypot bool   `json:"potential_honeypot"`
	HoneypotReason    string `json:"honeypot_reason,omitempty"`
}

// PortScanner coordinates parallel TCP audits on multiple hosts.
type PortScanner struct {
	workers          int
	rateLimit        int
	timeout          time.Duration
	bannerTimeout    time.Duration
	progressCallback func(completed int, total int, open int, elapsed time.Duration)
	progressInterval time.Duration
}

// NewPortScanner constructs a PortScanner session.
func NewPortScanner(workers int, rateLimit int, timeoutSeconds int) *PortScanner {
	if workers <= 0 {
		workers = 100
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 3
	}
	return &PortScanner{
		workers:       workers,
		rateLimit:     rateLimit,
		timeout:       time.Duration(timeoutSeconds) * time.Second,
		bannerTimeout: 2 * time.Second,
	}
}

// SetProgressCallback reports long-running scan progress at a fixed interval.
func (ps *PortScanner) SetProgressCallback(callback func(completed int, total int, open int, elapsed time.Duration)) {
	ps.progressCallback = callback
	ps.progressInterval = 30 * time.Second
}

// ScanJob bundles a target address and port number.
type ScanJob struct {
	Target ScanTarget
	Port   int
}

// ScanTarget preserves both the logical domain and the concrete address being scanned.
type ScanTarget struct {
	Domain  string
	Address string
}

// ScanBatch runs concurrent port audits on all target/port combinations.
func (ps *PortScanner) ScanBatch(ctx context.Context, targets []string, ports []int) []PortResult {
	scanTargets := make([]ScanTarget, 0, len(targets))
	for _, target := range targets {
		scanTargets = append(scanTargets, ScanTarget{Domain: target, Address: target})
	}
	return ps.ScanResolvedBatch(ctx, scanTargets, ports)
}

// ScanResolvedBatch runs concurrent port audits over explicit domain/address pairs.
func (ps *PortScanner) ScanResolvedBatch(ctx context.Context, targets []ScanTarget, ports []int) []PortResult {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []PortResult
	totalJobs := len(targets) * len(ports)
	if totalJobs == 0 {
		return results
	}

	// Fill job queue
	jobs := make(chan ScanJob, totalJobs)
	for _, t := range targets {
		for _, p := range ports {
			jobs <- ScanJob{Target: t, Port: p}
		}
	}
	close(jobs)

	sem := make(chan struct{}, ps.workers)
	var ticker *time.Ticker
	if ps.rateLimit > 0 {
		interval := time.Second / time.Duration(ps.rateLimit)
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}
	var completedCount atomic.Int64
	var openCount atomic.Int64
	startedAt := time.Now()
	progressDone := make(chan struct{})
	if ps.progressCallback != nil {
		interval := ps.progressInterval
		if interval <= 0 {
			interval = 30 * time.Second
		}
		ps.progressCallback(0, totalJobs, 0, 0)
		progressTicker := time.NewTicker(interval)
		defer progressTicker.Stop()
		go func() {
			for {
				select {
				case <-progressTicker.C:
					ps.progressCallback(
						int(completedCount.Load()),
						totalJobs,
						int(openCount.Load()),
						time.Since(startedAt),
					)
				case <-progressDone:
					return
				}
			}
		}()
	}

	for job := range jobs {
		select {
		case <-ctx.Done():
			if ps.progressCallback != nil {
				close(progressDone)
				ps.progressCallback(int(completedCount.Load()), totalJobs, int(openCount.Load()), time.Since(startedAt))
			}
			return results
		default:
		}

		if ticker != nil {
			<-ticker.C
		}

		sem <- struct{}{}
		wg.Add(1)

		go func(j ScanJob) {
			defer func() {
				<-sem
				wg.Done()
			}()

			res := ps.ScanSingle(ctx, j.Target, j.Port)
			if res != nil && res.State == "open" {
				openCount.Add(1)
				mu.Lock()
				results = append(results, *res)
				mu.Unlock()
			}
			completedCount.Add(1)
		}(job)
	}

	wg.Wait()
	if ps.progressCallback != nil {
		close(progressDone)
		ps.progressCallback(int(completedCount.Load()), totalJobs, int(openCount.Load()), time.Since(startedAt))
	}
	return results
}

// ScanSingle probes a single TCP port using a safe socket connect.
func (ps *PortScanner) ScanSingle(ctx context.Context, target ScanTarget, port int) *PortResult {
	address := net.JoinHostPort(target.Address, strconv.Itoa(port))
	dialer := &net.Dialer{
		Timeout: ps.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		state, reason := classifyDialError(err)
		return &PortResult{
			Domain:  target.Domain,
			Address: target.Address,
			Port:    port,
			State:   state,
			Reason:  reason,
		}
	}
	defer conn.Close()

	ip := ""
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip = tcpAddr.IP.String()
	}

	serverName := target.Domain
	if serverName == "" {
		serverName = target.Address
	}
	fp := GrabBanner(conn, serverName, port, ps.bannerTimeout)
	if fp.Service == "" {
		fp.Service = IdentifyService(port, fp.Banner)
	}
	honeypot, honeypotReason := detect.DetectPotentialHoneypotWithContext(port, fp.Service, fp.Banner, fp.Product)

	return &PortResult{
		Domain:            target.Domain,
		Address:           target.Address,
		IP:                ip,
		Port:              port,
		State:             "open",
		Reason:            "connect_success",
		Service:           fp.Service,
		Product:           fp.Product,
		Version:           fp.Version,
		Banner:            fp.Banner,
		PotentialHoneypot: honeypot,
		HoneypotReason:    honeypotReason,
	}
}

func classifyDialError(err error) (string, string) {
	if err == nil {
		return "closed", ""
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return "filtered", "context_deadline"
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "filtered", "connect_timeout"
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Timeout() {
			return "filtered", "connect_timeout"
		}
		if strings.Contains(strings.ToLower(opErr.Err.Error()), "refused") {
			return "closed", "connection_refused"
		}
	}

	if errors.Is(err, os.ErrDeadlineExceeded) {
		return "filtered", "connect_timeout"
	}

	if strings.Contains(strings.ToLower(err.Error()), "refused") {
		return "closed", "connection_refused"
	}

	return "closed", "connect_error"
}
