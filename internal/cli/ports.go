package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"nullfinder/internal/logx"
	"nullfinder/internal/output"
	"nullfinder/internal/portscan"
)

var (
	PortsInput       string
	PortsProfile     string
	PortsList        string
	PortsProfileFlag string
)

var portsCmd = &cobra.Command{
	Use:   "ports",
	Short: "Perform safe TCP connect port scanning",
	Long:  `Scans open TCP ports using non-raw connect connections, maps banners, and flags potential services. No stealth scan or raw sockets.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logx.Log.Info().Msg("Starting port scanning process...")

		if PortsInput == "" {
			return fmt.Errorf("input file must be specified with --input")
		}

		lines, err := readLines(PortsInput)
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}

		if len(lines) == 0 {
			logx.Log.Warn().Msg("Input file is empty")
			return nil
		}

		// Determine ports
		var ports []int
		if PortsList != "" {
			parts := strings.Split(PortsList, ",")
			for _, pStr := range parts {
				p, err := strconv.Atoi(strings.TrimSpace(pStr))
				if err == nil {
					ports = append(ports, p)
				}
			}
		} else {
			profile := PortsProfile
			if PortsProfileFlag != "" {
				profile = PortsProfileFlag
			}
			if strings.ToLower(profile) == "common" {
				ports = Cfg.PortScan.CommonPorts
			} else {
				ports = Cfg.PortScan.WebPorts
			}
		}

		if len(ports) == 0 {
			return fmt.Errorf("no ports configured or specified for scanning")
		}

		// Initialize scanner
		scanner := portscan.NewPortScanner(
			Cfg.PortScan.Workers,
			Cfg.PortScan.RateLimitPerSecond,
			Cfg.PortScan.TimeoutSeconds,
		)

		// Output manager
		pm, err := output.NewPathManager("port-scan", OutputDir)
		if err != nil {
			return fmt.Errorf("failed to initialize output: %w", err)
		}
		if err := pm.InitDirectories(); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		logx.Log.Info().Str("scan_id", pm.ScanID).Msg("Port scan session initialized")

		ctx := context.Background()
		targets := portscan.ExpandTargets(ctx, lines)
		results := scanner.ScanResolvedBatch(ctx, targets, ports)

		var openLines []string
		var honeypotLines []string
		for _, r := range results {
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
			openLines = append(openLines, fmt.Sprintf("%s:%d (%s)%s%s", endpoint, r.Port, r.Service, productSnippet, bannerSnippet))
			if r.PotentialHoneypot {
				honeypotLines = append(honeypotLines, fmt.Sprintf("%s:%d (%s) -> %s", endpoint, r.Port, r.Service, r.HoneypotReason))
			}
		}

		// Write results to files
		if err := output.WriteLines(pm.GetFilePath("open_ports.txt"), openLines); err != nil {
			logx.Log.Error().Err(err).Msg("Failed to write open_ports.txt")
		}
		if len(honeypotLines) > 0 {
			if err := output.WriteLines(pm.GetFilePath("honeypot_ports.txt"), honeypotLines); err != nil {
				logx.Log.Error().Err(err).Msg("Failed to write honeypot_ports.txt")
			}
		}

		jsonData, err := json.MarshalIndent(results, "", "  ")
		if err == nil {
			jsonPath := pm.GetFilePath("portscan_results.json")
			if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
				logx.Log.Error().Err(err).Msg("Failed to write portscan_results.json")
			}
		}

		fmt.Printf("\nPort Scanning Completed\n\n")
		fmt.Printf("Scan ID: %s\n", pm.ScanID)
		fmt.Printf("Total targets scanned: %d\n", len(targets))
		fmt.Printf("Open TCP ports discovered: %d\n", len(results))
		fmt.Printf("Potential honeypot ports detected: %d\n", len(honeypotLines))
		fmt.Printf("Results written to: %s/\n", pm.BaseDir)

		return nil
	},
}

func init() {
	portsCmd.Flags().StringVar(&PortsInput, "input", "", "input file containing resolved hosts to port scan (required)")
	portsCmd.Flags().StringVar(&PortsProfile, "profile", "web", "scanning profile (web, common)")
	portsCmd.Flags().StringVar(&PortsProfileFlag, "port-profile", "", "scanning profile (web, common)")
	portsCmd.Flags().StringVar(&PortsList, "ports-list", "", "custom comma-separated list of ports")

	RootCmd.AddCommand(portsCmd)
}
