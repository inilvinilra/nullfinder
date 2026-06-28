package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"nullfinder/internal/dns"
	"nullfinder/internal/enum/passive"
	"nullfinder/internal/httpprobe"
	"nullfinder/internal/logx"
	"nullfinder/internal/output"
	"nullfinder/internal/portscan"
	"nullfinder/internal/report"
	scanpkg "nullfinder/internal/scan"
	"nullfinder/internal/scope"
	"nullfinder/internal/storage"
)

var (
	// Scan subcommand flags
	ScanDomain           string
	ScanInput            string
	ScanMode             string
	ScanProfile          string
	ScanWordlist         string
	ScanActive           bool
	ScanPassive          bool
	ScanHTTP             bool
	ScanNoHTTP           bool
	ScanPorts            bool
	ScanNoPorts          bool
	ScanSafeOnly         bool
	ScanMaxDepth         int
	ScanProviders        string
	DisableExternal      bool
	EnableCrtsh          bool
	EnableWebarchive     bool
	EnableSecuritytrails bool
	EnableCensys         bool
	EnableShodan         bool
	EnableHackerTarget   bool
	EnableAnubis         bool
	EnableAlienVault     bool
	EnableThreatCrowd    bool
	EnableCertSpotter    bool
	EnableURLScan        bool
	EnableCommonCrawl    bool
	EnableRapidDNS       bool
	EnableTHC            bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Perform a full reconnaissance pipeline scan",
	Long: `Runs the complete pipeline on the specified target. Depending on the mode,
this includes scope validation, passive OSINT source querying, DNS resolution, HTTP probing,
safe TCP port checking, vulnerability-free scoring, and full report writing.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logx.Log.Info().Msg("Initializing NullFinder scan orchestration...")

		if ScanDomain == "" && ScanInput == "" {
			return fmt.Errorf("either --domain or --input must be specified")
		}

		var inScope []string
		var outOfScope []string
		var targetName string
		var err error

		if ScanDomain != "" {
			inScope = []string{ScanDomain, "*." + ScanDomain}
			targetName = ScanDomain
		} else {
			inScope, outOfScope, err = scope.ParseScopeFile(ScanInput)
			if err != nil {
				return fmt.Errorf("failed to parse scope file: %w", err)
			}
			targetName = "file-import"
			if len(inScope) > 0 {
				_, root := scope.NormalizeDomain(inScope[0])
				if root != "" {
					targetName = root
				}
			}
		}

		// Create PathManager
		pm, err := output.NewPathManager(targetName, OutputDir)
		if err != nil {
			return fmt.Errorf("failed to initialize output manager: %w", err)
		}
		if err := pm.InitDirectories(); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		logx.Log.Info().Str("scan_id", pm.ScanID).Msg("Scan session directories initialized")

		ctx := context.Background()

		// Dynamic provider overrides via CLI flags
		if DisableExternal {
			Cfg.Providers.Crtsh.Enabled = false
			Cfg.Providers.WebArchive.Enabled = false
			Cfg.Providers.SecurityTrails.Enabled = false
			Cfg.Providers.Censys.Enabled = false
			Cfg.Providers.Shodan.Enabled = false
			Cfg.Providers.HackerTarget.Enabled = false
			Cfg.Providers.Anubis.Enabled = false
			Cfg.Providers.AlienVault.Enabled = false
			Cfg.Providers.ThreatCrowd.Enabled = false
			Cfg.Providers.CertSpotter.Enabled = false
			Cfg.Providers.URLScan.Enabled = false
			Cfg.Providers.CommonCrawl.Enabled = false
			Cfg.Providers.RapidDNS.Enabled = false
			Cfg.Providers.THC.Enabled = false
		} else {
			if EnableCrtsh {
				Cfg.Providers.Crtsh.Enabled = true
			}
			if EnableWebarchive {
				Cfg.Providers.WebArchive.Enabled = true
			}
			if EnableSecuritytrails {
				Cfg.Providers.SecurityTrails.Enabled = true
			}
			if EnableCensys {
				Cfg.Providers.Censys.Enabled = true
			}
			if EnableShodan {
				Cfg.Providers.Shodan.Enabled = true
			}
			if EnableHackerTarget {
				Cfg.Providers.HackerTarget.Enabled = true
			}
			if EnableAnubis {
				Cfg.Providers.Anubis.Enabled = true
			}
			if EnableAlienVault {
				Cfg.Providers.AlienVault.Enabled = true
			}
			if EnableThreatCrowd {
				Cfg.Providers.ThreatCrowd.Enabled = true
			}
			if EnableCertSpotter {
				Cfg.Providers.CertSpotter.Enabled = true
			}
			if EnableURLScan {
				Cfg.Providers.URLScan.Enabled = true
			}
			if EnableCommonCrawl {
				Cfg.Providers.CommonCrawl.Enabled = true
			}
			if EnableRapidDNS {
				Cfg.Providers.RapidDNS.Enabled = true
			}
			if EnableTHC {
				Cfg.Providers.THC.Enabled = true
			}
		}

		// Override providers if --providers is passed
		if cmd.Flags().Changed("providers") {
			parts := strings.Split(ScanProviders, ",")
			Cfg.Providers.Crtsh.Enabled = false
			Cfg.Providers.WebArchive.Enabled = false
			Cfg.Providers.SecurityTrails.Enabled = false
			Cfg.Providers.Censys.Enabled = false
			Cfg.Providers.Shodan.Enabled = false
			Cfg.Providers.HackerTarget.Enabled = false
			Cfg.Providers.Anubis.Enabled = false
			Cfg.Providers.AlienVault.Enabled = false
			Cfg.Providers.ThreatCrowd.Enabled = false
			Cfg.Providers.CertSpotter.Enabled = false
			Cfg.Providers.URLScan.Enabled = false
			Cfg.Providers.CommonCrawl.Enabled = false
			Cfg.Providers.RapidDNS.Enabled = false
			Cfg.Providers.THC.Enabled = false

			for _, p := range parts {
				p = strings.TrimSpace(strings.ToLower(p))
				switch p {
				case "crtsh":
					Cfg.Providers.Crtsh.Enabled = true
				case "webarchive":
					Cfg.Providers.WebArchive.Enabled = true
				case "securitytrails":
					Cfg.Providers.SecurityTrails.Enabled = true
				case "censys":
					Cfg.Providers.Censys.Enabled = true
				case "shodan":
					Cfg.Providers.Shodan.Enabled = true
				case "hackertarget":
					Cfg.Providers.HackerTarget.Enabled = true
				case "anubis":
					Cfg.Providers.Anubis.Enabled = true
				case "alienvault":
					Cfg.Providers.AlienVault.Enabled = true
				case "threatcrowd":
					Cfg.Providers.ThreatCrowd.Enabled = true
				case "certspotter":
					Cfg.Providers.CertSpotter.Enabled = true
				case "urlscan":
					Cfg.Providers.URLScan.Enabled = true
				case "commoncrawl":
					Cfg.Providers.CommonCrawl.Enabled = true
				case "rapiddns":
					Cfg.Providers.RapidDNS.Enabled = true
				case "thc":
					Cfg.Providers.THC.Enabled = true
				}
			}
		}

		forceActive := cmd.Flags().Changed("active") && ScanActive
		forcePassive := cmd.Flags().Changed("passive") && ScanPassive
		settings := scanpkg.ResolveDiscoverySettings(ScanMode, Cfg, forceActive, forcePassive, ScanMaxDepth)
		if DisableExternal {
			settings.PassiveEnabled = false
		}

		resolvers := dns.EffectiveResolvers(Cfg.DNS.ResolverMode, Cfg.DNS.Resolvers, nil, Cfg.DNS.FallbackPublicResolvers)
		passive.Configure(Cfg)
		discovery, err := scanpkg.DiscoverAssets(ctx, Cfg, scanpkg.DiscoveryOptions{
			InScope:    inScope,
			OutOfScope: outOfScope,
			Mode:       ScanMode,
			Wordlist:   ScanWordlist,
			Resolvers:  resolvers,
			RateLimit:  Cfg.Scan.RateLimitPerSecond,
			Settings:   settings,
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

		httpEnabled := Cfg.HTTP.Enabled
		if cmd.Flags().Changed("http") {
			httpEnabled = ScanHTTP
		}
		if ScanNoHTTP {
			httpEnabled = false
		}
		if httpEnabled {
			logx.Log.Info().Int("count", len(resolvedSubdomains)).Msg("Running HTTP/HTTPS service probing...")
			prober := httpprobe.NewProber(
				Cfg.HTTP.Ports,
				Cfg.Scan.Threads,
				Cfg.Scan.RateLimitPerSecond,
				Cfg.HTTP.TimeoutSeconds,
				Cfg.HTTP.FollowRedirects,
				Cfg.HTTP.MaxRedirects,
				resolvers,
			)
			probeResults = prober.ProbeBatch(ctx, resolvedSubdomains)
			for _, res := range probeResults {
				liveURLs = append(liveURLs, res.URL)
				if res.IsInteresting {
					interestingURLs = append(interestingURLs, fmt.Sprintf("%s [%d] (%s) -> %s", res.URL, res.StatusCode, res.Title, res.InterestingReason))
				}
			}

			if err := output.WriteLines(pm.GetFilePath("live_urls.txt"), liveURLs); err != nil {
				logx.Log.Error().Err(err).Msg("Failed to write live_urls.txt")
			}
			if len(interestingURLs) > 0 {
				if err := output.WriteLines(pm.GetFilePath("interesting_urls.txt"), interestingURLs); err != nil {
					logx.Log.Error().Err(err).Msg("Failed to write interesting_urls.txt")
				}
			}
			jsonData, err := json.MarshalIndent(probeResults, "", "  ")
			if err == nil {
				jsonPath := pm.GetFilePath("http_responses.json")
				_ = os.WriteFile(jsonPath, jsonData, 0644)
			}
		}

		// 6. TCP Port Scanning
		var portscanResults []portscan.PortResult
		var openPortsLines []string

		portsEnabled := Cfg.PortScan.Enabled
		if cmd.Flags().Changed("ports") {
			portsEnabled = ScanPorts
		}
		if ScanNoPorts {
			portsEnabled = false
		}
		if portsEnabled {
			logx.Log.Info().Int("count", len(resolvedSubdomains)).Msg("Running safe TCP port scan...")

			var scanPorts []int
			if strings.ToLower(ScanProfile) == "common" {
				scanPorts = Cfg.PortScan.CommonPorts
			} else {
				scanPorts = Cfg.PortScan.WebPorts
			}

			scanner := portscan.NewPortScanner(
				Cfg.PortScan.Workers,
				Cfg.PortScan.RateLimitPerSecond,
				Cfg.PortScan.TimeoutSeconds,
			)

			scanTargets := scanpkg.BuildPortScanTargets(resolvedSubdomains, finalDnsResults)
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

			if err := output.WriteLines(pm.GetFilePath("open_ports.txt"), openPortsLines); err != nil {
				logx.Log.Error().Err(err).Msg("Failed to write open_ports.txt")
			}

			jsonData, err := json.MarshalIndent(portscanResults, "", "  ")
			if err == nil {
				jsonPath := pm.GetFilePath("portscan_results.json")
				_ = os.WriteFile(jsonPath, jsonData, 0644)
			}
		}

		// 7. Save Findings to Bbolt Database & Generate Reports
		var dbAssets []storage.AssetRecord
		for _, sub := range resolvedSubdomains {
			var ips []string
			var cnames []string

			for _, dnsRes := range finalDnsResults {
				if dnsRes.Domain == sub {
					ips = append(ips, dnsRes.IPs...)
					if dnsRes.CNAME != "" {
						cnames = append(cnames, dnsRes.CNAME)
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
				CNAMEs:            cnames,
				Ports:             ports,
				Schemes:           schemes,
				FinalURLs:         finalURLs,
				StatusCodes:       statusCodes,
				Titles:            titles,
				Servers:           servers,
				PoweredBy:         dedupeStrings(poweredBy),
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
		db, err := storage.NewBoltDB(Cfg.Storage.Path)
		if err == nil {
			defer db.Close()
			_ = db.SaveScan(pm.ScanID, targetName, ScanMode)
			for _, asset := range dbAssets {
				_ = db.SaveAsset(pm.ScanID, asset)
			}
		}

		// Write results to disk
		if err := output.WriteLines(pm.GetFilePath("all_subdomains.txt"), allSubs); err != nil {
			logx.Log.Error().Err(err).Msg("Failed to write all_subdomains.txt")
		}
		if len(candidateSubs) > 0 {
			if err := output.WriteLines(pm.GetFilePath("candidate_subdomains.txt"), candidateSubs); err != nil {
				logx.Log.Error().Err(err).Msg("Failed to write candidate_subdomains.txt")
			}
		}
		if err := output.WriteLines(pm.GetFilePath("resolved_subdomains.txt"), resolvedSubdomains); err != nil {
			logx.Log.Error().Err(err).Msg("Failed to write resolved_subdomains.txt")
		}
		if len(wildcardSubdomains) > 0 {
			if err := output.WriteLines(pm.GetFilePath("wildcard_subdomains.txt"), wildcardSubdomains); err != nil {
				logx.Log.Error().Err(err).Msg("Failed to write wildcard_subdomains.txt")
			}
		}
		if len(cnames) > 0 {
			if err := output.WriteLines(pm.GetFilePath("cnames.txt"), cnames); err != nil {
				logx.Log.Error().Err(err).Msg("Failed to write cnames.txt")
			}
		}

		// Compile report formats
		_ = report.ExportJSON(pm.GetFilePath("report.json"), dbAssets)
		_ = report.ExportYAML(pm.GetFilePath("report.yaml"), dbAssets)
		_ = report.ExportCSV(pm.GetFilePath("report.csv"), dbAssets)
		_ = report.ExportTXT(pm.GetFilePath("report.txt"), targetName, pm.ScanID, dbAssets)
		_ = report.ExportHTML(pm.GetFilePath("report.html"), targetName, pm.ScanID, dbAssets)

		// Print final output summary
		fmt.Printf("\nNullFinder Pipeline Scan Completed\n\n")
		fmt.Printf("Root domain: %s\n", targetName)
		fmt.Printf("Scan ID: %s\n", pm.ScanID)
		fmt.Printf("Mode: %s\n", ScanMode)
		fmt.Printf("All discovered subdomains: %d\n", len(allSubs))
		fmt.Printf("Resolved subdomains (clean): %d\n", len(resolvedSubdomains))
		if httpEnabled {
			fmt.Printf("Active HTTP services: %d\n", len(liveURLs))
			fmt.Printf("Interesting web interfaces: %d\n", len(interestingURLs))
		}
		if portsEnabled {
			fmt.Printf("Open TCP ports: %d\n", len(portscanResults))
		}
		fmt.Printf("Wildcard subdomains: %d\n", len(wildcardSubdomains))
		fmt.Printf("Results written to: %s/\n", pm.BaseDir)

		return nil
	},
}

func init() {
	scanCmd.Flags().StringVar(&ScanDomain, "domain", "", "target domain (e.g., example.com)")
	scanCmd.Flags().StringVar(&ScanInput, "input", "", "file path containing scope targets")
	scanCmd.Flags().StringVar(&ScanMode, "mode", "hybrid", "discovery mode (local, passive, hybrid, full)")
	scanCmd.Flags().StringVar(&ScanProfile, "profile", "web", "scan profile (e.g. web, common)")
	scanCmd.Flags().StringVar(&ScanWordlist, "wordlist", "", "custom wordlist for local discovery")
	scanCmd.Flags().BoolVar(&ScanActive, "active", false, "force active scans")
	scanCmd.Flags().BoolVar(&ScanPassive, "passive", false, "force passive enumeration")
	scanCmd.Flags().BoolVar(&ScanHTTP, "http", true, "probe HTTP/HTTPS services")
	scanCmd.Flags().BoolVar(&ScanNoHTTP, "no-http", false, "skip HTTP/HTTPS probing")
	scanCmd.Flags().BoolVar(&ScanPorts, "ports", false, "enable safe TCP port checks")
	scanCmd.Flags().BoolVar(&ScanNoPorts, "no-ports", false, "skip safe TCP port checks")
	scanCmd.Flags().BoolVar(&ScanSafeOnly, "safe-only", true, "run security-safe scans only")
	scanCmd.Flags().IntVar(&ScanMaxDepth, "max-depth", 1, "maximum recursion depth for discovery")
	scanCmd.Flags().StringVar(&ScanProviders, "providers", "", "comma-separated lists of third-party APIs to query")
	scanCmd.Flags().BoolVar(&DisableExternal, "disable-external", false, "block all external API lookups")

	// Individual passive provider enablers
	scanCmd.Flags().BoolVar(&EnableCrtsh, "enable-crtsh", false, "enable crt.sh provider")
	scanCmd.Flags().BoolVar(&EnableWebarchive, "enable-webarchive", false, "enable webarchive provider")
	scanCmd.Flags().BoolVar(&EnableSecuritytrails, "enable-securitytrails", false, "enable securitytrails provider")
	scanCmd.Flags().BoolVar(&EnableCensys, "enable-censys", false, "enable censys provider")
	scanCmd.Flags().BoolVar(&EnableShodan, "enable-shodan", false, "enable shodan provider")
	scanCmd.Flags().BoolVar(&EnableHackerTarget, "enable-hackertarget", false, "enable hackertarget provider")
	scanCmd.Flags().BoolVar(&EnableAnubis, "enable-anubis", false, "enable anubis provider")
	scanCmd.Flags().BoolVar(&EnableAlienVault, "enable-alienvault", false, "enable alienvault provider")
	scanCmd.Flags().BoolVar(&EnableThreatCrowd, "enable-threatcrowd", false, "enable threatcrowd provider")
	scanCmd.Flags().BoolVar(&EnableCertSpotter, "enable-certspotter", false, "enable certspotter provider")
	scanCmd.Flags().BoolVar(&EnableURLScan, "enable-urlscan", false, "enable urlscan provider")
	scanCmd.Flags().BoolVar(&EnableCommonCrawl, "enable-commoncrawl", false, "enable commoncrawl provider")
	scanCmd.Flags().BoolVar(&EnableRapidDNS, "enable-rapiddns", false, "enable rapiddns provider")
	scanCmd.Flags().BoolVar(&EnableTHC, "enable-thc", false, "enable thc provider")

	RootCmd.AddCommand(scanCmd)
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
