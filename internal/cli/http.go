package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"nullfinder/internal/httpprobe"
	"nullfinder/internal/logx"
	"nullfinder/internal/output"
)

var (
	HTTPInput string
	HTTPPorts string
)

var httpCmd = &cobra.Command{
	Use:   "http",
	Short: "Probe HTTP/HTTPS web services",
	Long:  `Probes web ports of target hosts, validating TLS credentials, collecting titles, mapping response header parameters, and identifying interesting paths.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logx.Log.Info().Msg("Starting HTTP/HTTPS web services probe...")

		if HTTPInput == "" {
			return fmt.Errorf("input file must be specified with --input")
		}

		// Read domains/IPs from input file
		lines, err := readLines(HTTPInput)
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}

		if len(lines) == 0 {
			logx.Log.Warn().Msg("Input file is empty")
			return nil
		}

		// Determine ports
		ports := Cfg.HTTP.Ports
		if HTTPPorts != "" {
			parts := strings.Split(HTTPPorts, ",")
			var parsedPorts []int
			for _, pStr := range parts {
				p, err := strconv.Atoi(strings.TrimSpace(pStr))
				if err == nil {
					parsedPorts = append(parsedPorts, p)
				}
			}
			if len(parsedPorts) > 0 {
				ports = parsedPorts
			}
		}

		// Initialize prober
		prober := httpprobe.NewProber(
			ports,
			Cfg.Scan.Threads,
			RateLimit,
			Cfg.HTTP.TimeoutSeconds,
			Cfg.HTTP.FollowRedirects,
			Cfg.HTTP.MaxRedirects,
			Cfg.DNS.Resolvers,
		)

		// Initialize output PathManager
		pm, err := output.NewPathManager("http-probe", OutputDir)
		if err != nil {
			return fmt.Errorf("failed to initialize output: %w", err)
		}
		if err := pm.InitDirectories(); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		logx.Log.Info().Str("scan_id", pm.ScanID).Msg("HTTP probe session initialized")

		ctx := context.Background()
		results := prober.ProbeBatch(ctx, lines)

		var liveURLs []string
		var interestingURLs []string
		var honeypotURLs []string

		for _, res := range results {
			liveURLs = append(liveURLs, res.URL)
			if res.IsInteresting {
				interestingURLs = append(interestingURLs, fmt.Sprintf("%s [%d] (%s) -> %s", res.URL, res.StatusCode, res.Title, res.InterestingReason))
			}
			if res.PotentialHoneypot {
				honeypotURLs = append(honeypotURLs, fmt.Sprintf("%s [%d] -> %s", res.URL, res.StatusCode, res.HoneypotReason))
			}
		}

		// Save results to files
		if err := output.WriteLines(pm.GetFilePath("live_urls.txt"), liveURLs); err != nil {
			logx.Log.Error().Err(err).Msg("Failed to write live_urls.txt")
		}

		if len(interestingURLs) > 0 {
			if err := output.WriteLines(pm.GetFilePath("interesting_urls.txt"), interestingURLs); err != nil {
				logx.Log.Error().Err(err).Msg("Failed to write interesting_urls.txt")
			}
		}
		if len(honeypotURLs) > 0 {
			if err := output.WriteLines(pm.GetFilePath("honeypot_urls.txt"), honeypotURLs); err != nil {
				logx.Log.Error().Err(err).Msg("Failed to write honeypot_urls.txt")
			}
		}

		// Write structured JSON output
		jsonData, err := json.MarshalIndent(results, "", "  ")
		if err == nil {
			jsonPath := pm.GetFilePath("http_responses.json")
			if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
				logx.Log.Error().Err(err).Msg("Failed to write http_responses.json")
			}
		}

		fmt.Printf("\nHTTP Probing Completed\n\n")
		fmt.Printf("Scan ID: %s\n", pm.ScanID)
		fmt.Printf("Total targets probed: %d\n", len(lines))
		fmt.Printf("Active web services discovered: %d\n", len(liveURLs))
		fmt.Printf("Interesting web interfaces flagged: %d\n", len(interestingURLs))
		fmt.Printf("Potential honeypots detected: %d\n", len(honeypotURLs))
		fmt.Printf("Results written to: %s/\n", pm.BaseDir)

		return nil
	},
}

func init() {
	httpCmd.Flags().StringVar(&HTTPInput, "input", "", "input file containing resolved domains/IPs to probe (required)")
	httpCmd.Flags().StringVar(&HTTPPorts, "ports", "", "comma-separated list of web ports to probe (e.g. 80,443,8080)")

	RootCmd.AddCommand(httpCmd)
}
