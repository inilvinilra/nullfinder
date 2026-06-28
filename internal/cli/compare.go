package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"nullfinder/internal/dns"
	"nullfinder/internal/logx"
	"nullfinder/internal/output"
)

var (
	CompareDomainsFile string
	CompareIPsFile     string
	CompareName        string
	CompareMode        string
	CompareProfile     string
	ComparePorts       string
)

type compareSummary struct {
	NullFinderAssets        int               `json:"nullfinder_assets"`
	NullFinderResolved      int               `json:"nullfinder_resolved"`
	NullFinderOpenPorts     int               `json:"nullfinder_open_ports"`
	NullFinderLiveHTTP      int               `json:"nullfinder_live_http"`
	NullFinderHoneypots     int               `json:"nullfinder_honeypots"`
	SubdomainToolCounts     map[string]int    `json:"subdomain_tool_counts"`
	SubdomainVerifiedCounts map[string]int    `json:"subdomain_verified_counts"`
	ExternalPortToolCounts  map[string]int    `json:"external_port_tool_counts"`
	ToolErrors              map[string]string `json:"tool_errors"`
	ComparisonHosts         int               `json:"comparison_hosts"`
	ComparisonIPs           int               `json:"comparison_ips"`
}

var compareCmd = &cobra.Command{
	Use:   "compare",
	Short: "Run sequential external-tool comparison against NullFinder",
	Long: `Runs subdomain tools first, consolidates and verifies their outputs, then executes
port and HTTP comparison stages with NullFinder and external tools in sequence.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logx.Log.Info().Msg("Initializing NullFinder comparison orchestration...")

		ctx := context.Background()
		batchResult, err := runBatchPipeline(ctx, batchRunOptions{
			DomainsFile: CompareDomainsFile,
			IPsFile:     CompareIPsFile,
			Name:        CompareName,
			Mode:        CompareMode,
			Profile:     CompareProfile,
		})
		if err != nil {
			return err
		}

		compareDir := filepath.Join(batchResult.PathManager.BaseDir, "comparison")
		if err := os.MkdirAll(compareDir, 0755); err != nil {
			return fmt.Errorf("failed to create comparison directory: %w", err)
		}

		summary := compareSummary{
			NullFinderAssets:        len(batchResult.Assets),
			NullFinderResolved:      len(batchResult.ResolvedSubdomains),
			NullFinderOpenPorts:     len(batchResult.PortResults),
			NullFinderLiveHTTP:      len(batchResult.ProbeResults),
			NullFinderHoneypots:     countHoneypotAssets(batchResult.Assets),
			SubdomainToolCounts:     make(map[string]int),
			SubdomainVerifiedCounts: make(map[string]int),
			ExternalPortToolCounts:  make(map[string]int),
			ToolErrors:              make(map[string]string),
		}

		domains, err := readLines(CompareDomainsFile)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to read domains file: %w", err)
		}

		toolOutputs := make(map[string][]string)
		for _, domain := range domains {
			domainKey := sanitizeName(domain)
			if ok, path, errText := runSubdomainTool(ctx, compareDir, "subfinder-"+domainKey, 2*time.Minute, "subfinder", "-d", domain, "-all", "-silent"); ok {
				lines := mustReadLines(path)
				summary.SubdomainToolCounts["subfinder"] += len(lines)
				toolOutputs["subfinder"] = append(toolOutputs["subfinder"], lines...)
			} else if errText != "" {
				summary.ToolErrors["subfinder"] = joinReason(summary.ToolErrors["subfinder"], errText)
			}
			if ok, path, errText := runSubdomainTool(ctx, compareDir, "assetfinder-"+domainKey, 1*time.Minute, "assetfinder", "--subs-only", domain); ok {
				lines := mustReadLines(path)
				summary.SubdomainToolCounts["assetfinder"] += len(lines)
				toolOutputs["assetfinder"] = append(toolOutputs["assetfinder"], lines...)
			} else if errText != "" {
				summary.ToolErrors["assetfinder"] = joinReason(summary.ToolErrors["assetfinder"], errText)
			}
			if ok, path, errText := runSubdomainTool(ctx, compareDir, "amass-"+domainKey, 3*time.Minute, "amass", "enum", "-passive", "-d", domain, "-nocolor"); ok {
				lines := mustReadLines(path)
				summary.SubdomainToolCounts["amass"] += len(lines)
				toolOutputs["amass"] = append(toolOutputs["amass"], lines...)
			} else if errText != "" {
				summary.ToolErrors["amass"] = joinReason(summary.ToolErrors["amass"], errText)
			}
		}

		union := dedupeStrings(flattenToolOutputs(toolOutputs))
		unionPath := filepath.Join(compareDir, "external_subdomains_union.txt")
		if len(union) > 0 {
			_ = output.WriteLines(unionPath, union)
		}

		verified := union
		if len(union) > 0 {
			if commandExists("dnsx") {
				verifiedPath := filepath.Join(compareDir, "external_subdomains_verified.txt")
				if err := runCommandToFile(ctx, 2*time.Minute, compareDir, verifiedPath, "dnsx", "-silent", "-l", unionPath, "-retry", "2", "-rl", "20"); err == nil {
					verified = mustReadLines(verifiedPath)
				} else {
					summary.ToolErrors["dnsx"] = err.Error()
				}
			} else {
				verified = verifyWithInternalResolver(ctx, union)
			}
		}
		if len(verified) > 0 {
			_ = output.WriteLines(filepath.Join(compareDir, "external_subdomains_verified.txt"), verified)
		}

		for tool, lines := range toolOutputs {
			summary.SubdomainVerifiedCounts[tool] = countIntersection(lines, verified)
		}

		compareHosts := dedupeStrings(append(append([]string{}, batchResult.ResolvedSubdomains...), batchResult.DirectHosts...))
		compareHosts = dedupeStrings(append(compareHosts, verified...))
		compareHostsPath := filepath.Join(compareDir, "comparison_hosts.txt")
		if len(compareHosts) > 0 {
			_ = output.WriteLines(compareHostsPath, compareHosts)
		}

		compareIPs := buildComparisonIPs(ctx, compareHosts, batchResult.DirectHosts)
		summary.ComparisonHosts = len(compareHosts)
		summary.ComparisonIPs = len(compareIPs)
		compareIPsPath := filepath.Join(compareDir, "comparison_ips.txt")
		if len(compareIPs) > 0 {
			_ = output.WriteLines(compareIPsPath, compareIPs)
		}

		ports := comparePortsValue()
		if commandExists("naabu") && len(compareHosts) > 0 {
			path := filepath.Join(compareDir, "naabu.txt")
			if err := runCommandToFile(ctx, 2*time.Minute, compareDir, path, "naabu", "-silent", "-list", compareHostsPath, "-p", ports, "-rate", "50"); err == nil {
				summary.ExternalPortToolCounts["naabu"] = countNonEmptyLines(path)
			} else {
				summary.ToolErrors["naabu"] = err.Error()
			}
		}
		if commandExists("nmap") && len(compareHosts) > 0 {
			path := filepath.Join(compareDir, "nmap.txt")
			if err := runCommandWithBuiltinOutput(ctx, 3*time.Minute, compareDir, path, "nmap", "-Pn", "-p", ports, "-iL", compareHostsPath, "-oN", path); err == nil {
				summary.ExternalPortToolCounts["nmap"] = countNmapOpen(path)
			} else {
				summary.ToolErrors["nmap"] = err.Error()
			}
		}
		if commandExists("rustscan") && len(compareHosts) > 0 {
			path := filepath.Join(compareDir, "rustscan.txt")
			argHosts := strings.Join(compareHosts, ",")
			if err := runCommandToFile(ctx, 90*time.Second, compareDir, path, "rustscan", "-a", argHosts, "-p", ports, "-g", "--no-banner", "--ulimit", "256", "--batch-size", "10", "--timeout", "2000", "--tries", "1", "--scan-order", "serial"); err == nil {
				summary.ExternalPortToolCounts["rustscan"] = countNonEmptyLines(path)
			} else {
				summary.ToolErrors["rustscan"] = err.Error()
			}
		}
		if commandExists("masscan") && len(compareIPs) > 0 {
			path := filepath.Join(compareDir, "masscan.txt")
			if err := runCommandWithBuiltinOutput(ctx, 90*time.Second, compareDir, path, "masscan", "-p"+ports, "-iL", compareIPsPath, "--rate", "200", "-oL", path); err == nil {
				summary.ExternalPortToolCounts["masscan"] = countPrefixedLines(path, "open")
			} else {
				summary.ToolErrors["masscan"] = err.Error()
			}
		}

		summaryPath := filepath.Join(compareDir, "comparison_summary.json")
		if data, err := json.MarshalIndent(summary, "", "  "); err == nil {
			_ = os.WriteFile(summaryPath, data, 0644)
		}
		_ = output.WriteLines(filepath.Join(compareDir, "comparison_summary.txt"), renderCompareSummary(summary))

		fmt.Printf("\nNullFinder Compare Completed\n\n")
		fmt.Printf("Base Scan ID: %s\n", batchResult.PathManager.ScanID)
		fmt.Printf("Comparison directory: %s\n", compareDir)
		fmt.Printf("NullFinder assets: %d\n", summary.NullFinderAssets)
		fmt.Printf("External comparison hosts: %d\n", summary.ComparisonHosts)
		fmt.Printf("External comparison IPs: %d\n", summary.ComparisonIPs)
		fmt.Printf("Results written to: %s/\n", batchResult.PathManager.BaseDir)

		return nil
	},
}

func init() {
	compareCmd.Flags().StringVar(&CompareDomainsFile, "domains-file", "targets/domains.txt", "file containing one domain per line")
	compareCmd.Flags().StringVar(&CompareIPsFile, "ips-file", "targets/ips.txt", "file containing one IP or IP:port per line")
	compareCmd.Flags().StringVar(&CompareName, "name", "comparison-targets", "label used for the comparison scan ID prefix")
	compareCmd.Flags().StringVar(&CompareMode, "mode", "hybrid", "discovery mode for domain targets (local, passive, hybrid, full)")
	compareCmd.Flags().StringVar(&CompareProfile, "profile", "web", "port profile to use for automated IP analysis (web, common)")
	compareCmd.Flags().StringVar(&ComparePorts, "ports", "", "custom comparison port list (e.g. 80,443,8080,8443)")
	RootCmd.AddCommand(compareCmd)
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func runSubdomainTool(ctx context.Context, dir string, label string, timeout time.Duration, command string, args ...string) (bool, string, string) {
	path := filepath.Join(dir, label+".txt")
	if err := runCommandToFile(ctx, timeout, dir, path, command, args...); err != nil {
		return false, "", err.Error()
	}
	return true, path, ""
}

func runCommandToFile(ctx context.Context, timeout time.Duration, dir string, outputPath string, command string, args ...string) error {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, command, args...)
	cmd.Dir = dir
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	stderrPath := outputPath + ".stderr.log"
	stderrFile, err := os.Create(stderrPath)
	if err != nil {
		return err
	}
	defer stderrFile.Close()

	cmd.Stdout = outputFile
	cmd.Stderr = stderrFile
	if err := cmd.Run(); err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("%s timed out", command)
		}
		stderrPreview, readErr := os.ReadFile(stderrPath)
		if readErr == nil {
			message := strings.TrimSpace(string(stderrPreview))
			if message != "" {
				return fmt.Errorf("%s failed: %s", command, firstLine(message))
			}
		}
		return fmt.Errorf("%s failed", command)
	}
	return nil
}

func runCommandWithBuiltinOutput(ctx context.Context, timeout time.Duration, dir string, outputPath string, command string, args ...string) error {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, command, args...)
	cmd.Dir = dir

	stderrPath := outputPath + ".stderr.log"
	stderrFile, err := os.Create(stderrPath)
	if err != nil {
		return err
	}
	defer stderrFile.Close()

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer devNull.Close()

	cmd.Stdout = devNull
	cmd.Stderr = stderrFile
	if err := cmd.Run(); err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("%s timed out", command)
		}
		stderrPreview, readErr := os.ReadFile(stderrPath)
		if readErr == nil {
			message := strings.TrimSpace(string(stderrPreview))
			if message != "" {
				return fmt.Errorf("%s failed: %s", command, firstLine(message))
			}
		}
		return fmt.Errorf("%s failed", command)
	}
	return nil
}

func mustReadLines(path string) []string {
	lines, err := readLines(path)
	if err != nil {
		return nil
	}
	return dedupeStrings(lines)
}

func flattenToolOutputs(inputs map[string][]string) []string {
	var all []string
	for _, lines := range inputs {
		all = append(all, lines...)
	}
	return all
}

func verifyWithInternalResolver(ctx context.Context, hosts []string) []string {
	resolvers := dns.EffectiveResolvers(Cfg.DNS.ResolverMode, Cfg.DNS.Resolvers, nil, Cfg.DNS.FallbackPublicResolvers)
	resolver := dns.NewResolver(resolvers, Cfg.Scan.Threads, Cfg.Scan.RateLimitPerSecond, Cfg.DNS.TimeoutSeconds)
	results := resolver.ResolveBatch(ctx, hosts)
	var verified []string
	for _, result := range results {
		if result.Resolved {
			verified = append(verified, result.Domain)
		}
	}
	return dedupeStrings(verified)
}

func buildComparisonIPs(ctx context.Context, hosts []string, directHosts []string) []string {
	resolvers := dns.EffectiveResolvers(Cfg.DNS.ResolverMode, Cfg.DNS.Resolvers, nil, Cfg.DNS.FallbackPublicResolvers)
	resolver := dns.NewResolver(resolvers, Cfg.Scan.Threads, Cfg.Scan.RateLimitPerSecond, Cfg.DNS.TimeoutSeconds)
	results := resolver.ResolveBatch(ctx, hosts)
	ipSet := make(map[string]struct{})
	for _, host := range directHosts {
		if net.ParseIP(host) != nil {
			ipSet[host] = struct{}{}
		}
	}
	for _, result := range results {
		for _, ip := range result.IPs {
			ipSet[ip] = struct{}{}
		}
	}
	var ips []string
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return ips
}

func countIntersection(lines []string, verified []string) int {
	set := make(map[string]struct{}, len(verified))
	for _, line := range verified {
		set[line] = struct{}{}
	}
	count := 0
	for _, line := range dedupeStrings(lines) {
		if _, ok := set[line]; ok {
			count++
		}
	}
	return count
}

func comparePortsValue() string {
	if strings.TrimSpace(ComparePorts) != "" {
		return ComparePorts
	}
	ports := batchPorts(CompareProfile, map[int]struct{}{})
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, strconv.Itoa(port))
	}
	return strings.Join(parts, ",")
}

func countNonEmptyLines(path string) int {
	return len(mustReadLines(path))
}

func countNmapOpen(path string) int {
	lines := mustReadLines(path)
	count := 0
	for _, line := range lines {
		if strings.Contains(line, "/tcp") && strings.Contains(line, " open ") {
			count++
		}
	}
	return count
}

func countPrefixedLines(path string, prefix string) int {
	lines := mustReadLines(path)
	count := 0
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			count++
		}
	}
	return count
}

func sanitizeName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, ".", "-")
	value = strings.ReplaceAll(value, ":", "-")
	return value
}

func firstLine(value string) string {
	if idx := strings.IndexByte(value, '\n'); idx >= 0 {
		return strings.TrimSpace(value[:idx])
	}
	return strings.TrimSpace(value)
}

func renderCompareSummary(summary compareSummary) []string {
	var lines []string
	lines = append(lines, fmt.Sprintf("NullFinder assets: %d", summary.NullFinderAssets))
	lines = append(lines, fmt.Sprintf("NullFinder resolved subdomains: %d", summary.NullFinderResolved))
	lines = append(lines, fmt.Sprintf("NullFinder open ports: %d", summary.NullFinderOpenPorts))
	lines = append(lines, fmt.Sprintf("NullFinder live HTTP: %d", summary.NullFinderLiveHTTP))
	lines = append(lines, fmt.Sprintf("NullFinder honeypots: %d", summary.NullFinderHoneypots))
	lines = append(lines, fmt.Sprintf("Comparison hosts: %d", summary.ComparisonHosts))
	lines = append(lines, fmt.Sprintf("Comparison IPs: %d", summary.ComparisonIPs))

	appendMap := func(title string, values map[string]int) {
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		lines = append(lines, title)
		for _, key := range keys {
			lines = append(lines, fmt.Sprintf("- %s: %d", key, values[key]))
		}
	}

	appendMap("Subdomain tool counts", summary.SubdomainToolCounts)
	appendMap("Verified subdomain counts", summary.SubdomainVerifiedCounts)
	appendMap("External port tool counts", summary.ExternalPortToolCounts)

	if len(summary.ToolErrors) > 0 {
		keys := make([]string, 0, len(summary.ToolErrors))
		for key := range summary.ToolErrors {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		lines = append(lines, "Tool errors")
		for _, key := range keys {
			lines = append(lines, fmt.Sprintf("- %s: %s", key, summary.ToolErrors[key]))
		}
	}

	return lines
}
