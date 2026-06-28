package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"nullfinder/internal/dns"
	"nullfinder/internal/enum/passive"
	"nullfinder/internal/httpprobe"
	"nullfinder/internal/logx"
	"nullfinder/internal/output"
	"nullfinder/internal/portscan"
	"nullfinder/internal/report"
	scanpkg "nullfinder/internal/scan"
	"nullfinder/internal/storage"
)

var (
	BatchDomainsFile    string
	BatchIPsFile        string
	BatchName           string
	BatchMode           string
	BatchProfile        string
	BatchPorts          string
	BatchSkipPorts      bool
	BatchMaxPortTargets int
)

type batchRunOptions struct {
	DomainsFile    string
	IPsFile        string
	Name           string
	Mode           string
	Profile        string
	Ports          string
	SkipPorts      bool
	MaxPortTargets int
}

type batchRunResult struct {
	PathManager         *output.PathManager
	Domains             []string
	DirectHosts         []string
	ResolvedSubdomains  []string
	WildcardSubdomains  []string
	AllSubdomains       []string
	CandidateSubdomains []string
	ScanTargets         []portscan.ScanTarget
	ProbeResults        []httpprobe.ProbeResult
	PortResults         []portscan.PortResult
	Assets              []storage.AssetRecord
}

type directIPTarget struct {
	Host         string
	ExplicitPort int
}

var batchCmd = &cobra.Command{
	Use:   "batch",
	Short: "Run an automated domain and IP orchestration pipeline",
	Long: `Consumes domain and IP target files, performs domain discovery, forwards resolved IPs
into HTTP/port analysis, merges direct IP targets, and generates a single consolidated report.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logx.Log.Info().Msg("Initializing NullFinder batch orchestration...")
		ctx := context.Background()
		result, err := runBatchPipeline(ctx, batchRunOptions{
			DomainsFile:    BatchDomainsFile,
			IPsFile:        BatchIPsFile,
			Name:           BatchName,
			Mode:           BatchMode,
			Profile:        BatchProfile,
			Ports:          BatchPorts,
			SkipPorts:      BatchSkipPorts,
			MaxPortTargets: BatchMaxPortTargets,
		})
		if err != nil {
			return err
		}

		fmt.Printf("\nNullFinder Batch Pipeline Completed\n\n")
		fmt.Printf("Scan ID: %s\n", result.PathManager.ScanID)
		fmt.Printf("Domains loaded: %d\n", len(result.Domains))
		fmt.Printf("Direct IP targets loaded: %d\n", len(result.DirectHosts))
		fmt.Printf("Resolved domain assets: %d\n", len(result.ResolvedSubdomains))
		fmt.Printf("Combined scan targets: %d\n", len(result.ScanTargets))
		fmt.Printf("Active HTTP services: %d\n", len(result.ProbeResults))
		fmt.Printf("Open TCP ports: %d\n", len(result.PortResults))
		fmt.Printf("Potential honeypots: %d\n", countHoneypotAssets(result.Assets))
		fmt.Printf("Results written to: %s/\n", result.PathManager.BaseDir)

		return nil
	},
}

func init() {
	batchCmd.Flags().StringVar(&BatchDomainsFile, "domains-file", "targets/domains.txt", "file containing one domain per line")
	batchCmd.Flags().StringVar(&BatchIPsFile, "ips-file", "targets/ips.txt", "file containing one IP or IP:port per line")
	batchCmd.Flags().StringVar(&BatchName, "name", "batch-targets", "label used for the batch scan ID prefix")
	batchCmd.Flags().StringVar(&BatchMode, "mode", "hybrid", "discovery mode for domain targets (local, passive, hybrid, full)")
	batchCmd.Flags().StringVar(&BatchProfile, "profile", "web", "port profile to use for automated IP analysis (web, common)")
	batchCmd.Flags().StringVar(&BatchPorts, "ports", "", "custom TCP port list for batch port analysis (e.g. 80,443,8080,8443)")
	batchCmd.Flags().BoolVar(&BatchSkipPorts, "skip-portscan", false, "skip TCP port analysis and still generate HTTP/DNS reports")
	batchCmd.Flags().IntVar(&BatchMaxPortTargets, "max-port-targets", 0, "maximum number of resolved targets to port scan (0 means unlimited)")
	RootCmd.AddCommand(batchCmd)
}

func buildBatchScope(domains []string) []string {
	seen := make(map[string]struct{})
	var scopeList []string
	for _, domain := range domains {
		normalized := strings.TrimSpace(domain)
		if normalized == "" {
			continue
		}
		for _, candidate := range []string{normalized, "*." + normalized} {
			if _, ok := seen[candidate]; ok {
				continue
			}
			seen[candidate] = struct{}{}
			scopeList = append(scopeList, candidate)
		}
	}
	return scopeList
}

func readDirectIPTargets(path string) ([]directIPTarget, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	var targets []directIPTarget
	for _, line := range lines {
		host, port, ok := parseDirectIPTarget(line)
		if !ok {
			continue
		}
		targets = append(targets, directIPTarget{Host: host, ExplicitPort: port})
	}
	return targets, nil
}

func parseDirectIPTarget(raw string) (string, int, bool) {
	value := strings.TrimSpace(raw)
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimPrefix(value, "https://")
	if idx := strings.IndexAny(value, "/?#"); idx != -1 {
		value = value[:idx]
	}

	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), 0, true
	}

	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		parts := strings.Split(value, ":")
		if len(parts) == 2 {
			if ip := net.ParseIP(parts[0]); ip != nil {
				port, convErr := strconv.Atoi(parts[1])
				if convErr == nil && port > 0 && port <= 65535 {
					return ip.String(), port, true
				}
			}
		}
		return "", 0, false
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return "", 0, false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, false
	}
	return ip.String(), port, true
}

func dedupeScanTargets(targets []portscan.ScanTarget) []portscan.ScanTarget {
	seen := make(map[portscan.ScanTarget]struct{})
	var deduped []portscan.ScanTarget
	for _, target := range targets {
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		deduped = append(deduped, target)
	}
	return deduped
}

func batchPorts(profile string, explicit map[int]struct{}) []int {
	var ports []int
	if strings.ToLower(profile) == "common" {
		ports = append(ports, Cfg.PortScan.CommonPorts...)
	} else {
		ports = append(ports, Cfg.PortScan.WebPorts...)
	}
	for port := range explicit {
		ports = append(ports, port)
	}
	return dedupeInts(ports)
}

func parsePortList(raw string) ([]int, error) {
	var ports []int
	seen := make(map[int]struct{})
	for _, part := range strings.Split(raw, ",") {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		port, err := strconv.Atoi(value)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port value: %s", value)
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports, nil
}

func batchHTTPPorts(explicit map[int]struct{}) []int {
	ports := append([]int{}, Cfg.HTTP.Ports...)
	for port := range explicit {
		ports = append(ports, port)
	}
	return dedupeInts(ports)
}

func dedupeInts(values []int) []int {
	seen := make(map[int]struct{})
	var out []int
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Ints(out)
	return out
}

func scanTargetStrings(targets []portscan.ScanTarget) []string {
	lines := make([]string, 0, len(targets))
	for _, target := range targets {
		if target.Domain != "" && target.Domain != target.Address {
			lines = append(lines, fmt.Sprintf("%s -> %s", target.Domain, target.Address))
			continue
		}
		lines = append(lines, target.Address)
	}
	sort.Strings(lines)
	return lines
}

func buildBatchAssets(resolvedSubdomains []string, dnsResults []dns.ResolutionResult, directHosts []string, probeResults []httpprobe.ProbeResult, portResults []portscan.PortResult) []storage.AssetRecord {
	assetMap := make(map[string]*storage.AssetRecord)

	ensureAsset := func(key string) *storage.AssetRecord {
		if asset, ok := assetMap[key]; ok {
			return asset
		}
		asset := &storage.AssetRecord{Domain: key}
		assetMap[key] = asset
		return asset
	}

	for _, domain := range resolvedSubdomains {
		ensureAsset(domain)
	}
	for _, host := range directHosts {
		ensureAsset(host)
	}
	for _, dnsResult := range dnsResults {
		asset := ensureAsset(dnsResult.Domain)
		asset.IPs = append(asset.IPs, dnsResult.IPs...)
		if dnsResult.CNAME != "" {
			asset.CNAMEs = append(asset.CNAMEs, dnsResult.CNAME)
		}
	}
	for _, result := range portResults {
		key := result.Domain
		if key == "" {
			key = result.Address
		}
		asset := ensureAsset(key)
		if result.IP != "" {
			asset.IPs = append(asset.IPs, result.IP)
		}
		if result.Address != "" && net.ParseIP(result.Address) != nil {
			asset.IPs = append(asset.IPs, result.Address)
		}
		asset.Ports = append(asset.Ports, result.Port)
		if result.PotentialHoneypot {
			asset.PotentialHoneypot = true
			asset.HoneypotReason = joinReason(asset.HoneypotReason, result.HoneypotReason)
		}
	}
	for _, result := range probeResults {
		asset := ensureAsset(result.Domain)
		if result.ResolvedIP != "" {
			asset.IPs = append(asset.IPs, result.ResolvedIP)
		}
		asset.Schemes = append(asset.Schemes, result.URL)
		if result.FinalURL != "" {
			asset.FinalURLs = append(asset.FinalURLs, result.FinalURL)
		}
		asset.StatusCodes = append(asset.StatusCodes, result.StatusCode)
		if result.Title != "" {
			asset.Titles = append(asset.Titles, result.Title)
		}
		if result.Server != "" {
			asset.Servers = append(asset.Servers, result.Server)
		}
		if result.PoweredBy != "" {
			asset.PoweredBy = append(asset.PoweredBy, result.PoweredBy)
		}
		asset.Technologies = append(asset.Technologies, result.Technologies...)
		if result.FaviconHash != "" {
			asset.FaviconHashes = append(asset.FaviconHashes, result.FaviconHash)
		}
		if result.ContentSecurityPolicy != "" {
			asset.CSPs = append(asset.CSPs, result.ContentSecurityPolicy)
		}
		if result.HasLoginForm {
			asset.HasLoginForm = true
		}
		if result.TLSIssuer != "" {
			asset.TLSIssuers = append(asset.TLSIssuers, result.TLSIssuer)
		}
		if result.TLSExpiry != "" {
			asset.TLSExpiries = append(asset.TLSExpiries, result.TLSExpiry)
		}
		if result.IsInteresting {
			asset.IsInteresting = true
			asset.InterestingReason = joinReason(asset.InterestingReason, result.InterestingReason)
		}
		if result.PotentialHoneypot {
			asset.PotentialHoneypot = true
			asset.HoneypotReason = joinReason(asset.HoneypotReason, result.HoneypotReason)
		}
	}

	keys := make([]string, 0, len(assetMap))
	for key := range assetMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	assets := make([]storage.AssetRecord, 0, len(keys))
	for _, key := range keys {
		asset := assetMap[key]
		asset.IPs = dedupeStrings(asset.IPs)
		asset.CNAMEs = dedupeStrings(asset.CNAMEs)
		asset.Schemes = dedupeStrings(asset.Schemes)
		asset.FinalURLs = dedupeStrings(asset.FinalURLs)
		asset.Titles = dedupeStrings(asset.Titles)
		asset.Servers = dedupeStrings(asset.Servers)
		asset.PoweredBy = dedupeStrings(asset.PoweredBy)
		asset.Technologies = dedupeStrings(asset.Technologies)
		asset.FaviconHashes = dedupeStrings(asset.FaviconHashes)
		asset.CSPs = dedupeStrings(asset.CSPs)
		asset.TLSIssuers = dedupeStrings(asset.TLSIssuers)
		asset.TLSExpiries = dedupeStrings(asset.TLSExpiries)
		asset.Ports = dedupeInts(asset.Ports)
		asset.StatusCodes = dedupeInts(asset.StatusCodes)
		assets = append(assets, *asset)
	}

	return assets
}

func countHoneypotAssets(assets []storage.AssetRecord) int {
	count := 0
	for _, asset := range assets {
		if asset.PotentialHoneypot {
			count++
		}
	}
	return count
}

func runBatchPipeline(ctx context.Context, opts batchRunOptions) (*batchRunResult, error) {
	domains, err := readLines(opts.DomainsFile)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read domains file: %w", err)
	}
	directTargets, err := readDirectIPTargets(opts.IPsFile)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read IP targets file: %w", err)
	}
	if len(domains) == 0 && len(directTargets) == 0 {
		return nil, fmt.Errorf("no targets loaded from %s or %s", opts.DomainsFile, opts.IPsFile)
	}

	targetName := opts.Name
	if targetName == "" {
		targetName = "batch-targets"
	}
	pm, err := output.NewPathManager(targetName, OutputDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize output manager: %w", err)
	}
	if err := pm.InitDirectories(); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}
	logx.Log.Info().Str("scan_id", pm.ScanID).Msg("Batch scan session directories initialized")

	resolvers := dns.EffectiveResolvers(Cfg.DNS.ResolverMode, Cfg.DNS.Resolvers, nil, Cfg.DNS.FallbackPublicResolvers)
	passive.Configure(Cfg)

	var discovery *scanpkg.DiscoveryResult
	if len(domains) > 0 {
		inScope := buildBatchScope(domains)
		settings := scanpkg.ResolveDiscoverySettings(opts.Mode, Cfg, false, false, Cfg.Scan.MaxDepth)
		discovery, err = scanpkg.DiscoverAssets(ctx, Cfg, scanpkg.DiscoveryOptions{
			InScope:   inScope,
			Mode:      opts.Mode,
			Wordlist:  Cfg.Enum.Wordlist,
			Resolvers: resolvers,
			RateLimit: Cfg.Scan.RateLimitPerSecond,
			Settings:  settings,
		})
		if err != nil {
			return nil, err
		}
	} else {
		discovery = &scanpkg.DiscoveryResult{}
	}

	resolvedSubdomains := discovery.ResolvedSubdomains
	wildcardSubdomains := discovery.WildcardSubdomains
	cnames := discovery.CNAMEs
	finalDNSResults := discovery.DNSResults
	allSubs := discovery.AllSubdomains
	candidateSubs := discovery.CandidateSubdomains

	if len(allSubs) > 0 {
		_ = output.WriteLines(pm.GetFilePath("all_subdomains.txt"), allSubs)
	}
	if len(candidateSubs) > 0 {
		_ = output.WriteLines(pm.GetFilePath("candidate_subdomains.txt"), candidateSubs)
	}
	if len(resolvedSubdomains) > 0 {
		_ = output.WriteLines(pm.GetFilePath("resolved_subdomains.txt"), resolvedSubdomains)
	}
	if len(wildcardSubdomains) > 0 {
		_ = output.WriteLines(pm.GetFilePath("wildcard_subdomains.txt"), wildcardSubdomains)
	}
	if len(cnames) > 0 {
		_ = output.WriteLines(pm.GetFilePath("cnames.txt"), cnames)
	}

	scanTargets := scanpkg.BuildPortScanTargets(resolvedSubdomains, finalDNSResults)
	explicitPorts := make(map[int]struct{})
	directHostSet := make(map[string]struct{})
	for _, target := range directTargets {
		scanTargets = append(scanTargets, portscan.ScanTarget{Domain: target.Host, Address: target.Host})
		directHostSet[target.Host] = struct{}{}
		if target.ExplicitPort > 0 {
			explicitPorts[target.ExplicitPort] = struct{}{}
		}
	}
	scanTargets = dedupeScanTargets(scanTargets)

	var directHosts []string
	for host := range directHostSet {
		directHosts = append(directHosts, host)
	}
	sort.Strings(directHosts)
	if len(directHosts) > 0 {
		_ = output.WriteLines(pm.GetFilePath("direct_ips.txt"), directHosts)
	}

	probeInputs := dedupeStrings(append(append([]string{}, resolvedSubdomains...), directHosts...))
	if lines := scanTargetStrings(scanTargets); len(lines) > 0 {
		_ = output.WriteLines(pm.GetFilePath("combined_targets.txt"), lines)
	}

	scanPorts := batchPorts(opts.Profile, explicitPorts)
	if strings.TrimSpace(opts.Ports) != "" {
		parsedPorts, err := parsePortList(opts.Ports)
		if err != nil {
			return nil, err
		}
		for port := range explicitPorts {
			parsedPorts = append(parsedPorts, port)
		}
		scanPorts = dedupeInts(parsedPorts)
	}
	httpPorts := batchHTTPPorts(explicitPorts)

	var probeResults []httpprobe.ProbeResult
	var liveURLs []string
	var interestingURLs []string
	var honeypotURLs []string
	if Cfg.HTTP.Enabled && len(probeInputs) > 0 {
		logx.Log.Info().Int("count", len(probeInputs)).Msg("Running automated HTTP/HTTPS probing...")
		prober := httpprobe.NewProber(
			httpPorts,
			Cfg.Scan.Threads,
			Cfg.Scan.RateLimitPerSecond,
			Cfg.HTTP.TimeoutSeconds,
			Cfg.HTTP.FollowRedirects,
			Cfg.HTTP.MaxRedirects,
			resolvers,
		)
		probeResults = prober.ProbeBatch(ctx, probeInputs)
		for _, res := range probeResults {
			liveURLs = append(liveURLs, res.URL)
			if res.IsInteresting {
				interestingURLs = append(interestingURLs, fmt.Sprintf("%s [%d] (%s) -> %s", res.URL, res.StatusCode, res.Title, res.InterestingReason))
			}
			if res.PotentialHoneypot {
				honeypotURLs = append(honeypotURLs, fmt.Sprintf("%s [%d] -> %s", res.URL, res.StatusCode, res.HoneypotReason))
			}
		}
		_ = output.WriteLines(pm.GetFilePath("live_urls.txt"), liveURLs)
		if len(interestingURLs) > 0 {
			_ = output.WriteLines(pm.GetFilePath("interesting_urls.txt"), interestingURLs)
		}
		if len(honeypotURLs) > 0 {
			_ = output.WriteLines(pm.GetFilePath("honeypot_urls.txt"), honeypotURLs)
		}
		if data, err := json.MarshalIndent(probeResults, "", "  "); err == nil {
			_ = os.WriteFile(pm.GetFilePath("http_responses.json"), data, 0644)
		}
	}

	var portResults []portscan.PortResult
	var openPortLines []string
	var honeypotPortLines []string
	portScanTargets := scanTargets
	if opts.MaxPortTargets > 0 && len(portScanTargets) > opts.MaxPortTargets {
		logx.Log.Warn().
			Int("targets", len(portScanTargets)).
			Int("max_targets", opts.MaxPortTargets).
			Msg("Limiting TCP port analysis target count")
		portScanTargets = portScanTargets[:opts.MaxPortTargets]
	}
	if opts.SkipPorts {
		logx.Log.Info().Msg("Skipping automated TCP port analysis by request")
	} else if len(portScanTargets) > 0 {
		totalJobs := len(portScanTargets) * len(scanPorts)
		logx.Log.Info().
			Int("targets", len(portScanTargets)).
			Int("ports", len(scanPorts)).
			Int("jobs", totalJobs).
			Str("profile", opts.Profile).
			Msg("Running automated TCP port analysis...")
		if totalJobs > 50000 {
			logx.Log.Warn().
				Int("jobs", totalJobs).
				Msg("Large TCP scan workload detected; consider --ports or --max-port-targets for faster first results")
		}
		scanner := portscan.NewPortScanner(
			Cfg.PortScan.Workers,
			Cfg.PortScan.RateLimitPerSecond,
			Cfg.PortScan.TimeoutSeconds,
		)
		scanner.SetProgressCallback(func(completed int, total int, open int, elapsed time.Duration) {
			percent := 0.0
			if total > 0 {
				percent = float64(completed) * 100 / float64(total)
			}
			logx.Log.Info().
				Int("completed", completed).
				Int("total", total).
				Int("open", open).
				Float64("percent", percent).
				Str("elapsed", elapsed.Round(time.Second).String()).
				Msg("TCP port analysis progress")
		})
		portResults = scanner.ScanResolvedBatch(ctx, portScanTargets, scanPorts)
		for _, res := range portResults {
			endpoint := res.Domain
			if res.Address != "" && res.Address != res.Domain {
				endpoint = fmt.Sprintf("%s [%s]", res.Domain, res.Address)
			}
			line := fmt.Sprintf("%s:%d (%s)", endpoint, res.Port, res.Service)
			if res.Product != "" {
				line += fmt.Sprintf(" | Product: %s", res.Product)
				if res.Version != "" {
					line += " " + res.Version
				}
			}
			if res.Banner != "" {
				clean := strings.ReplaceAll(res.Banner, "\n", " ")
				clean = strings.ReplaceAll(clean, "\r", " ")
				if len(clean) > 40 {
					clean = clean[:40] + "..."
				}
				line += fmt.Sprintf(" | Banner: %s", clean)
			}
			openPortLines = append(openPortLines, line)
			if res.PotentialHoneypot {
				honeypotPortLines = append(honeypotPortLines, fmt.Sprintf("%s:%d (%s) -> %s", endpoint, res.Port, res.Service, res.HoneypotReason))
			}
		}
		_ = output.WriteLines(pm.GetFilePath("open_ports.txt"), openPortLines)
		if len(honeypotPortLines) > 0 {
			_ = output.WriteLines(pm.GetFilePath("honeypot_ports.txt"), honeypotPortLines)
		}
		if data, err := json.MarshalIndent(portResults, "", "  "); err == nil {
			_ = os.WriteFile(pm.GetFilePath("portscan_results.json"), data, 0644)
		}
	}

	assets := buildBatchAssets(resolvedSubdomains, finalDNSResults, directHosts, probeResults, portResults)
	db, err := storage.NewBoltDB(Cfg.Storage.Path)
	if err == nil {
		defer db.Close()
		_ = db.SaveScan(pm.ScanID, targetName, opts.Mode)
		for _, asset := range assets {
			_ = db.SaveAsset(pm.ScanID, asset)
		}
	}

	_ = report.ExportJSON(pm.GetFilePath("report.json"), assets)
	_ = report.ExportYAML(pm.GetFilePath("report.yaml"), assets)
	_ = report.ExportCSV(pm.GetFilePath("report.csv"), assets)
	_ = report.ExportTXT(pm.GetFilePath("report.txt"), targetName, pm.ScanID, assets)
	_ = report.ExportHTML(pm.GetFilePath("report.html"), targetName, pm.ScanID, assets)

	return &batchRunResult{
		PathManager:         pm,
		Domains:             domains,
		DirectHosts:         directHosts,
		ResolvedSubdomains:  resolvedSubdomains,
		WildcardSubdomains:  wildcardSubdomains,
		AllSubdomains:       allSubs,
		CandidateSubdomains: candidateSubs,
		ScanTargets:         scanTargets,
		ProbeResults:        probeResults,
		PortResults:         portResults,
		Assets:              assets,
	}, nil
}
