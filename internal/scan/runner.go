package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"nullfinder/internal/config"
	"nullfinder/internal/dns"
	"nullfinder/internal/enum/passive"
	"nullfinder/internal/httpprobe"
	"nullfinder/internal/logx"
	"nullfinder/internal/output"
	"nullfinder/internal/portscan"
	"nullfinder/internal/report"
	"nullfinder/internal/storage"
)

// RunScanOptions defines configurable parameters for programmatic execution.
type RunScanOptions struct {
	Domain    string
	Mode      string
	OutputDir string
	ScanID    string
	RateLimit int
}

// RunScan executes the full reconnaissance pipeline programmatically.
func RunScan(ctx context.Context, cfg *config.Config, opts RunScanOptions) error {
	// Create PathManager
	pm, err := output.NewPathManager(opts.Domain, opts.OutputDir)
	if err != nil {
		return fmt.Errorf("failed to initialize output manager: %w", err)
	}
	if opts.ScanID != "" {
		pm.ScanID = opts.ScanID
		outDir := opts.OutputDir
		if outDir == "" {
			outDir = "results"
		}
		pm.BaseDir = filepath.Join(outDir, opts.ScanID)
	}
	if err := pm.InitDirectories(); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	logx.Log.Info().Str("scan_id", pm.ScanID).Str("domain", opts.Domain).Msg("Background scan session started")

	passive.Configure(cfg)
	resolvers := dns.EffectiveResolvers(cfg.DNS.ResolverMode, cfg.DNS.Resolvers, nil, cfg.DNS.FallbackPublicResolvers)
	settings := ResolveDiscoverySettings(opts.Mode, cfg, false, false, cfg.Scan.MaxDepth)
	rateLimit := opts.RateLimit
	if rateLimit <= 0 {
		rateLimit = cfg.Scan.RateLimitPerSecond
	}

	discovery, err := DiscoverAssets(ctx, cfg, DiscoveryOptions{
		InScope:   []string{opts.Domain, "*." + opts.Domain},
		Mode:      opts.Mode,
		Wordlist:  cfg.Enum.Wordlist,
		Resolvers: resolvers,
		RateLimit: rateLimit,
		Settings:  settings,
	})
	if err != nil {
		return err
	}

	resolvedSubdomains := discovery.ResolvedSubdomains
	wildcardSubdomains := discovery.WildcardSubdomains
	cnames := discovery.CNAMEs
	finalDnsResults := discovery.DNSResults
	allSubs := discovery.AllSubdomains
	candidateSubs := discovery.CandidateSubdomains

	// 5. HTTP Probing
	var liveURLs []string
	var interestingURLs []string
	var probeResults []httpprobe.ProbeResult

	if cfg.HTTP.Enabled {
		logx.Log.Info().Int("count", len(resolvedSubdomains)).Msg("Running HTTP/HTTPS service probing...")
		prober := httpprobe.NewProber(
			cfg.HTTP.Ports,
			cfg.Scan.Threads,
			rateLimit,
			cfg.HTTP.TimeoutSeconds,
			cfg.HTTP.FollowRedirects,
			cfg.HTTP.MaxRedirects,
			resolvers,
		)
		probeResults = prober.ProbeBatch(ctx, resolvedSubdomains)
		for _, res := range probeResults {
			liveURLs = append(liveURLs, res.URL)
			if res.IsInteresting {
				interestingURLs = append(interestingURLs, fmt.Sprintf("%s [%d] (%s) -> %s", res.URL, res.StatusCode, res.Title, res.InterestingReason))
			}
		}

		_ = output.WriteLines(pm.GetFilePath("live_urls.txt"), liveURLs)
		if len(interestingURLs) > 0 {
			_ = output.WriteLines(pm.GetFilePath("interesting_urls.txt"), interestingURLs)
		}
		jsonData, err := json.MarshalIndent(probeResults, "", "  ")
		if err == nil {
			_ = os.WriteFile(pm.GetFilePath("http_responses.json"), jsonData, 0644)
		}
	}

	// 6. TCP Port Scanning
	var portscanResults []portscan.PortResult
	var openPortsLines []string

	if cfg.PortScan.Enabled || opts.Mode == "full" {
		logx.Log.Info().Int("count", len(resolvedSubdomains)).Msg("Running safe TCP port scan...")
		var scanPorts []int
		if strings.ToLower(cfg.PortScan.Profile) == "common" {
			scanPorts = cfg.PortScan.CommonPorts
		} else {
			scanPorts = cfg.PortScan.WebPorts
		}

		scanner := portscan.NewPortScanner(
			cfg.PortScan.Workers,
			cfg.PortScan.RateLimitPerSecond,
			cfg.PortScan.TimeoutSeconds,
		)

		scanTargets := BuildPortScanTargets(resolvedSubdomains, finalDnsResults)
		portscanResults = scanner.ScanResolvedBatch(ctx, scanTargets, scanPorts)
		for _, r := range portscanResults {
			bannerSnippet := ""
			productSnippet := ""
			endpoint := r.Domain
			if r.Address != "" && r.Address != r.Domain {
				endpoint = fmt.Sprintf("%s [%s]", r.Domain, r.Address)
			}
			if r.Product != "" {
				productSnippet = fmt.Sprintf(" | Product: %s", r.Product)
				if r.Version != "" {
					productSnippet += " " + r.Version
				}
			}
			if r.Banner != "" {
				cleanBanner := strings.ReplaceAll(r.Banner, "\n", " ")
				cleanBanner = strings.ReplaceAll(cleanBanner, "\r", " ")
				if len(cleanBanner) > 40 {
					cleanBanner = cleanBanner[:40] + "..."
				}
				bannerSnippet = fmt.Sprintf(" | Banner: %s", cleanBanner)
			}
			openPortsLines = append(openPortsLines, fmt.Sprintf("%s:%d (%s)%s%s", endpoint, r.Port, r.Service, productSnippet, bannerSnippet))
		}

		_ = output.WriteLines(pm.GetFilePath("open_ports.txt"), openPortsLines)
		jsonData, err := json.MarshalIndent(portscanResults, "", "  ")
		if err == nil {
			_ = os.WriteFile(pm.GetFilePath("portscan_results.json"), jsonData, 0644)
		}
	}

	// 7. Save Findings to Bbolt Database & Generate Reports
	var dbAssets []storage.AssetRecord
	for _, sub := range resolvedSubdomains {
		var ips []string
		var cnamesList []string

		for _, dnsRes := range finalDnsResults {
			if dnsRes.Domain == sub {
				ips = append(ips, dnsRes.IPs...)
				if dnsRes.CNAME != "" {
					cnamesList = append(cnamesList, dnsRes.CNAME)
				}
			}
		}

		var ports []int
		var schemes []string
		var finalURLs []string
		var statusCodes []int
		var titles []string
		var servers []string
		var poweredBy []string
		var technologies []string
		var faviconHashes []string
		var csps []string
		var hasLoginForm bool
		var tlsIssuers []string
		var tlsExpiries []string
		var isInteresting bool
		var interestingReason string

		for _, pRes := range portscanResults {
			if pRes.Domain == sub {
				ports = append(ports, pRes.Port)
			}
		}

		for _, hRes := range probeResults {
			if hRes.Domain == sub {
				schemes = append(schemes, hRes.URL)
				if hRes.FinalURL != "" {
					finalURLs = append(finalURLs, hRes.FinalURL)
				}
				statusCodes = append(statusCodes, hRes.StatusCode)
				if hRes.Title != "" {
					titles = append(titles, hRes.Title)
				}
				if hRes.Server != "" {
					servers = append(servers, hRes.Server)
				}
				if hRes.PoweredBy != "" {
					poweredBy = append(poweredBy, hRes.PoweredBy)
				}
				if len(hRes.Technologies) > 0 {
					technologies = append(technologies, hRes.Technologies...)
				}
				if hRes.FaviconHash != "" {
					faviconHashes = append(faviconHashes, hRes.FaviconHash)
				}
				if hRes.ContentSecurityPolicy != "" {
					csps = append(csps, hRes.ContentSecurityPolicy)
				}
				if hRes.HasLoginForm {
					hasLoginForm = true
				}
				if hRes.TLSIssuer != "" {
					tlsIssuers = append(tlsIssuers, hRes.TLSIssuer)
				}
				if hRes.TLSExpiry != "" {
					tlsExpiries = append(tlsExpiries, hRes.TLSExpiry)
				}
				if hRes.IsInteresting {
					isInteresting = true
					interestingReason = hRes.InterestingReason
				}
			}
		}

		dbAssets = append(dbAssets, storage.AssetRecord{
			Domain:            sub,
			IPs:               ips,
			CNAMEs:            cnamesList,
			Ports:             ports,
			Schemes:           schemes,
			FinalURLs:         finalURLs,
			StatusCodes:       statusCodes,
			Titles:            titles,
			Servers:           servers,
			PoweredBy:         poweredBy,
			Technologies:      dedupeStrings(technologies),
			FaviconHashes:     dedupeStrings(faviconHashes),
			CSPs:              dedupeStrings(csps),
			HasLoginForm:      hasLoginForm,
			TLSIssuers:        tlsIssuers,
			TLSExpiries:       tlsExpiries,
			IsInteresting:     isInteresting,
			InterestingReason: interestingReason,
		})
	}

	// Save to Bbolt database
	db, err := storage.NewBoltDB(cfg.Storage.Path)
	if err == nil {
		defer db.Close()
		_ = db.SaveScan(pm.ScanID, opts.Domain, opts.Mode)
		for _, asset := range dbAssets {
			_ = db.SaveAsset(pm.ScanID, asset)
		}
	}

	// Write results to disk
	_ = output.WriteLines(pm.GetFilePath("all_subdomains.txt"), allSubs)
	if len(candidateSubs) > 0 {
		_ = output.WriteLines(pm.GetFilePath("candidate_subdomains.txt"), candidateSubs)
	}
	_ = output.WriteLines(pm.GetFilePath("resolved_subdomains.txt"), resolvedSubdomains)
	if len(wildcardSubdomains) > 0 {
		_ = output.WriteLines(pm.GetFilePath("wildcard_subdomains.txt"), wildcardSubdomains)
	}
	if len(cnames) > 0 {
		_ = output.WriteLines(pm.GetFilePath("cnames.txt"), cnames)
	}

	// Compile report formats
	_ = report.ExportJSON(pm.GetFilePath("report.json"), dbAssets)
	_ = report.ExportYAML(pm.GetFilePath("report.yaml"), dbAssets)
	_ = report.ExportCSV(pm.GetFilePath("report.csv"), dbAssets)
	_ = report.ExportTXT(pm.GetFilePath("report.txt"), opts.Domain, pm.ScanID, dbAssets)
	_ = report.ExportHTML(pm.GetFilePath("report.html"), opts.Domain, pm.ScanID, dbAssets)

	logx.Log.Info().Str("scan_id", pm.ScanID).Msg("Scan completed and reports generated")
	return nil
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var out []string
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
