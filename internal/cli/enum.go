package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"nullfinder/internal/dns"
	"nullfinder/internal/enum"
	"nullfinder/internal/enum/passive"
	"nullfinder/internal/logx"
	"nullfinder/internal/output"
	scanpkg "nullfinder/internal/scan"
	"nullfinder/internal/scope"
)

type enumEvidenceRecord struct {
	Subdomain   string             `json:"subdomain"`
	Resolved    bool               `json:"resolved"`
	Wildcard    bool               `json:"wildcard"`
	IPs         []string           `json:"ips,omitempty"`
	CNAME       string             `json:"cname,omitempty"`
	NS          []string           `json:"ns,omitempty"`
	MX          []string           `json:"mx,omitempty"`
	Confidence  int                `json:"confidence"`
	SourceCount int                `json:"source_count"`
	Sources     []enum.AssetSource `json:"sources"`
}

var (
	EnumDomain    string
	EnumInput     string
	EnumMode      string
	EnumWordlist  string
	EnumProviders string
)

var enumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Perform subdomain enumeration on target domain",
	Long:  `Discovers subdomains using passive OSINT and local wordlist/permutation engines, matching findings against scope.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logx.Log.Info().Msg("Starting subdomain enumeration...")

		if EnumDomain == "" && EnumInput == "" {
			return fmt.Errorf("either --domain or --input must be specified")
		}

		var inScope []string
		var outOfScope []string
		var targetName string
		var err error

		if EnumDomain != "" {
			inScope = []string{EnumDomain, "*." + EnumDomain}
			targetName = EnumDomain
		} else {
			inScope, outOfScope, err = scope.ParseScopeFile(EnumInput)
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
			return fmt.Errorf("failed to initialize output directory manager: %w", err)
		}

		if err := pm.InitDirectories(); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		logx.Log.Info().Str("scan_id", pm.ScanID).Msg("Scan session directories initialized")

		// Dynamic provider override if CLI flag `--providers` is passed
		if cmd.Flags().Changed("providers") {
			parts := strings.Split(EnumProviders, ",")
			// Disable all first
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

			for _, part := range parts {
				part = strings.TrimSpace(strings.ToLower(part))
				switch part {
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

		// Disable all external APIs if requested (or local mode selected)
		if EnumMode == "local" {
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
		}

		settings := scanpkg.ResolveDiscoverySettings(EnumMode, Cfg, false, false, ScanMaxDepth)
		resolvers := dns.EffectiveResolvers(Cfg.DNS.ResolverMode, Cfg.DNS.Resolvers, nil, Cfg.DNS.FallbackPublicResolvers)
		passive.Configure(Cfg)

		discovery, err := scanpkg.DiscoverAssets(context.Background(), Cfg, scanpkg.DiscoveryOptions{
			InScope:    inScope,
			OutOfScope: outOfScope,
			Mode:       EnumMode,
			Wordlist:   EnumWordlist,
			Resolvers:  resolvers,
			RateLimit:  Cfg.Scan.RateLimitPerSecond,
			Settings:   settings,
		})
		if err != nil {
			return err
		}

		// Aggregate separate lists for file writing
		allSubs := discovery.AllSubdomains
		candidateSubs := discovery.CandidateSubdomains
		providerSubs := make(map[string][]string)

		for _, asset := range discovery.Assets {
			for _, src := range asset.Sources {
				providerSubs[src.Provider] = append(providerSubs[src.Provider], asset.Subdomain)
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
		if err := writeEnumEvidence(pm.GetFilePath("subdomain_evidence.json"), discovery); err != nil {
			logx.Log.Error().Err(err).Msg("Failed to write subdomain_evidence.json")
		}
		if err := writeProviderSummary(pm.GetFilePath("provider_summary.txt"), providerSubs); err != nil {
			logx.Log.Error().Err(err).Msg("Failed to write provider_summary.txt")
		}

		for prov, subs := range providerSubs {
			if len(subs) > 0 {
				filename := fmt.Sprintf("provider_%s.txt", prov)
				if err := output.WriteLines(pm.GetFilePath(filename), subs); err != nil {
					logx.Log.Error().Err(err).Str("provider", prov).Msg("Failed to write provider output file")
				}
			}
		}

		// Print final output summary
		fmt.Printf("\nScan completed\n\n")
		fmt.Printf("Root domain: %s\n", targetName)
		fmt.Printf("Scan ID: %s\n", pm.ScanID)
		fmt.Printf("Mode: %s\n", EnumMode)
		fmt.Printf("Subdomains found: %d\n", len(allSubs))
		fmt.Printf("Report path: %s/\n", pm.BaseDir)

		return nil
	},
}

func writeEnumEvidence(path string, discovery *scanpkg.DiscoveryResult) error {
	dnsIndex := make(map[string]dns.ResolutionResult, len(discovery.DNSResults))
	for _, dnsResult := range discovery.DNSResults {
		dnsIndex[dnsResult.Domain] = dnsResult
	}

	wildcardSet := make(map[string]struct{}, len(discovery.WildcardSubdomains))
	for _, entry := range discovery.WildcardSubdomains {
		host := strings.TrimSpace(strings.SplitN(entry, " -> ", 2)[0])
		if host != "" {
			wildcardSet[host] = struct{}{}
		}
	}

	records := make([]enumEvidenceRecord, 0, len(discovery.Assets))
	for _, asset := range discovery.Assets {
		dnsResult := dnsIndex[asset.Subdomain]
		_, wildcard := wildcardSet[asset.Subdomain]
		records = append(records, enumEvidenceRecord{
			Subdomain:   asset.Subdomain,
			Resolved:    dnsResult.Resolved,
			Wildcard:    wildcard,
			IPs:         dnsResult.IPs,
			CNAME:       dnsResult.CNAME,
			NS:          dnsResult.NS,
			MX:          dnsResult.MX,
			Confidence:  asset.Confidence,
			SourceCount: len(asset.Sources),
			Sources:     asset.Sources,
		})
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].Confidence == records[j].Confidence {
			return records[i].Subdomain < records[j].Subdomain
		}
		return records[i].Confidence > records[j].Confidence
	})

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func writeProviderSummary(path string, providerSubs map[string][]string) error {
	providers := make([]string, 0, len(providerSubs))
	for provider := range providerSubs {
		providers = append(providers, provider)
	}
	sort.Strings(providers)

	lines := []string{"Provider\tCount"}
	for _, provider := range providers {
		uniq := make(map[string]struct{})
		for _, subdomain := range providerSubs[provider] {
			uniq[subdomain] = struct{}{}
		}
		lines = append(lines, fmt.Sprintf("%s\t%d", provider, len(uniq)))
	}
	return output.WriteLines(path, lines)
}

func init() {
	enumCmd.Flags().StringVar(&EnumDomain, "domain", "", "target domain to enumerate")
	enumCmd.Flags().StringVar(&EnumInput, "input", "", "input scope file path")
	enumCmd.Flags().StringVar(&EnumMode, "mode", "hybrid", "discovery mode (local, passive, hybrid)")
	enumCmd.Flags().StringVar(&EnumWordlist, "wordlist", "", "custom wordlist path")
	enumCmd.Flags().StringVar(&EnumProviders, "providers", "", "comma-separated list of passive providers")

	RootCmd.AddCommand(enumCmd)
}
