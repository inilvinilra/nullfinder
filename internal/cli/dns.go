package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"nullfinder/internal/dns"
	"nullfinder/internal/logx"
	"nullfinder/internal/output"
	"nullfinder/internal/scope"
)

var (
	DNSInput        string
	DNSResolverMode string
	DNSResolvers    []string
)

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Resolve DNS records for subdomains list",
	Long:  `Performs multi-threaded DNS resolution querying A, AAAA, and CNAME records. Handles wildcard DNS detection.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logx.Log.Info().Msg("Starting DNS resolution...")

		if DNSInput == "" {
			return fmt.Errorf("input file must be specified with --input")
		}

		// Read subdomains to resolve
		lines, err := readLines(DNSInput)
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}

		if len(lines) == 0 {
			logx.Log.Warn().Msg("Input file is empty")
			return nil
		}

		// Determine resolvers
		resolvers := dns.EffectiveResolvers(DNSResolverMode, Cfg.DNS.Resolvers, DNSResolvers, Cfg.DNS.FallbackPublicResolvers)

		// Initialize resolver
		r := dns.NewResolver(resolvers, Cfg.Scan.Threads, RateLimit, Cfg.DNS.TimeoutSeconds)
		detector := dns.NewWildcardDetector(r)

		// Create PathManager
		pm, err := output.NewPathManager("dns-resolve", OutputDir)
		if err != nil {
			return fmt.Errorf("failed to initialize output manager: %w", err)
		}
		if err := pm.InitDirectories(); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		logx.Log.Info().Str("scan_id", pm.ScanID).Msg("DNS scan session initialized")

		// First, perform wildcard detection on all unique root domains found in the input
		ctx := context.Background()
		rootsChecked := make(map[string]bool)
		for _, line := range lines {
			_, root := scope.NormalizeDomain(line)
			if root != "" && !rootsChecked[root] {
				rootsChecked[root] = true
				isWildcard := detector.Detect(ctx, root)
				if isWildcard {
					logx.Log.Warn().Str("domain", root).Msg("Wildcard DNS detected on domain")
				}
			}
		}

		// Resolve batch
		logx.Log.Info().Int("count", len(lines)).Msg("Resolving subdomains...")
		results := r.ResolveBatch(ctx, lines)

		var resolved []string
		var wildcards []string
		var cnames []string

		for _, res := range results {
			if !res.Resolved {
				continue
			}

			// Check if it resolves to wildcard IPs
			if detector.IsWildcardIP(res.Domain, res.IPs) {
				logx.Log.Debug().Str("domain", res.Domain).Interface("ips", res.IPs).Msg("Subdomain matched wildcard IP footprint")
				wildcards = append(wildcards, fmt.Sprintf("%s -> %s", res.Domain, strings.Join(res.IPs, ", ")))
				continue
			}

			resolved = append(resolved, res.Domain)
			if res.CNAME != "" {
				cnames = append(cnames, fmt.Sprintf("%s -> %s", res.Domain, res.CNAME))
			}
		}

		// Write output files
		if err := output.WriteLines(pm.GetFilePath("resolved_subdomains.txt"), resolved); err != nil {
			logx.Log.Error().Err(err).Msg("Failed to write resolved_subdomains.txt")
		}
		if len(wildcards) > 0 {
			if err := output.WriteLines(pm.GetFilePath("wildcard_subdomains.txt"), wildcards); err != nil {
				logx.Log.Error().Err(err).Msg("Failed to write wildcard_subdomains.txt")
			}
		}
		if len(cnames) > 0 {
			if err := output.WriteLines(pm.GetFilePath("cnames.txt"), cnames); err != nil {
				logx.Log.Error().Err(err).Msg("Failed to write cnames.txt")
			}
		}

		// Print final output summary
		fmt.Printf("\nDNS Resolution Completed\n\n")
		fmt.Printf("Scan ID: %s\n", pm.ScanID)
		fmt.Printf("Total inputs: %d\n", len(lines))
		fmt.Printf("Resolved subdomains (clean): %d\n", len(resolved))
		fmt.Printf("Wildcard subdomains: %d\n", len(wildcards))
		fmt.Printf("Results written to: %s/\n", pm.BaseDir)

		return nil
	},
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "//") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func init() {
	dnsCmd.Flags().StringVar(&DNSInput, "input", "", "input file containing subdomains to resolve (required)")
	dnsCmd.Flags().StringVar(&DNSResolverMode, "dns-resolver-mode", "mixed", "dns resolver mode (system, custom, mixed)")
	dnsCmd.Flags().StringSliceVar(&DNSResolvers, "resolver", []string{}, "custom DNS resolver IP addresses")

	RootCmd.AddCommand(dnsCmd)
}
