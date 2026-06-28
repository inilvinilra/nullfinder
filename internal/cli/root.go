package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"nullfinder/internal/config"
	"nullfinder/internal/dns"
	"nullfinder/internal/enum/passive"
	"nullfinder/internal/logx"
	"nullfinder/internal/netutil"
)

var (
	// Global CLI Flag variables
	CfgFile    string
	OutputDir  string
	RateLimit  int
	Threads    int
	Timeout    int
	JSONLog    bool
	SilentLog  bool
	VerboseLog bool
	NoColorLog bool

	// Cfg stores the parsed configuration
	Cfg *config.Config
)

// RootCmd represents the base command executed without explicit subcommands.
var RootCmd = &cobra.Command{
	Use:   "nullfinder",
	Short: "NullFinder is a safe, scope-aware, native Go reconnaissance tool",
	Long: `NullFinder is a production-quality, cross-platform recon tool designed
exclusively for authorized bug bounty programs, asset inventory, and defensive testing.
It implements all discovery engines natively in Go without external CLI wrappers.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Load configuration file (falling back to standard names/defaults if not supplied)
		var err error
		Cfg, err = config.LoadConfig(CfgFile)
		if err != nil {
			return fmt.Errorf("failed to load configuration: %w", err)
		}

		// Override config options if explicit command-line overrides were supplied
		if cmd.Flags().Changed("threads") {
			Cfg.Scan.Threads = Threads
		}
		if cmd.Flags().Changed("timeout") {
			Cfg.Scan.TimeoutSeconds = Timeout
		}
		if cmd.Flags().Changed("rate-limit") {
			Cfg.Scan.RateLimitPerSecond = RateLimit
		}

		// Initialize Logger
		logx.InitLogger(VerboseLog, SilentLog, JSONLog, NoColorLog)

		// Set up custom resolver-aware HTTP client for passive providers
		resolvers := dns.EffectiveResolvers(Cfg.DNS.ResolverMode, Cfg.DNS.Resolvers, nil, Cfg.DNS.FallbackPublicResolvers)
		passive.HTTPClient = netutil.GetHTTPClient(resolvers, 10*time.Second, true)
		passive.Configure(Cfg)

		logx.Log.Debug().Msg("Logger and configuration system initialized")
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Execution error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	RootCmd.PersistentFlags().StringVar(&CfgFile, "config", "", "path to YAML configuration file")
	RootCmd.PersistentFlags().StringVar(&OutputDir, "output", "", "custom output folder")
	RootCmd.PersistentFlags().IntVar(&RateLimit, "rate-limit", 0, "maximum network queries per second")
	RootCmd.PersistentFlags().IntVar(&Threads, "threads", 0, "concurrency worker limit")
	RootCmd.PersistentFlags().IntVar(&Timeout, "timeout", 0, "global operation timeout (seconds)")
	RootCmd.PersistentFlags().BoolVar(&JSONLog, "json", false, "output logs in structured JSON format")
	RootCmd.PersistentFlags().BoolVar(&SilentLog, "silent", false, "suppress console logs")
	RootCmd.PersistentFlags().BoolVar(&VerboseLog, "verbose", false, "display detailed debug logs")
	RootCmd.PersistentFlags().BoolVar(&NoColorLog, "no-color", false, "disable console color highlighting")
}
