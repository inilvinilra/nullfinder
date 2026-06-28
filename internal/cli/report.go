package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"nullfinder/internal/logx"
	"nullfinder/internal/report"
	"nullfinder/internal/storage"
)

var (
	ReportScanID string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate reports for a completed scan session",
	Long:  `Retrieves saved scan history and logs from storage using the Scan ID and compiles the reports.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logx.Log.Info().Msg("Retrieving database logs to generate report...")

		if ReportScanID == "" {
			return fmt.Errorf("--scan-id is required")
		}

		// Connect to Bbolt
		db, err := storage.NewBoltDB(Cfg.Storage.Path)
		if err != nil {
			return fmt.Errorf("failed to open database: %w", err)
		}
		defer db.Close()

		// Retrieve scan
		scanRec, err := db.GetScan(ReportScanID)
		if err != nil {
			return fmt.Errorf("scan ID %q not found in database: %w", ReportScanID, err)
		}

		// Retrieve assets
		assets, err := db.GetAssets(ReportScanID)
		if err != nil {
			return fmt.Errorf("failed to load assets for scan %q: %w", ReportScanID, err)
		}

		if len(assets) == 0 {
			logx.Log.Warn().Msg("No assets found for the specified scan ID")
		}

		// Initialize output folder using scan ID
		baseDir := OutputDir
		if baseDir == "" {
			baseDir = filepath.Join("results", ReportScanID)
		}
		if err := os.MkdirAll(baseDir, 0755); err != nil {
			return fmt.Errorf("failed to create report directory: %w", err)
		}

		// Generate reports
		jsonPath := filepath.Join(baseDir, "report.json")
		if err := report.ExportJSON(jsonPath, assets); err != nil {
			logx.Log.Error().Err(err).Msg("Failed to write report.json")
		}

		yamlPath := filepath.Join(baseDir, "report.yaml")
		if err := report.ExportYAML(yamlPath, assets); err != nil {
			logx.Log.Error().Err(err).Msg("Failed to write report.yaml")
		}

		csvPath := filepath.Join(baseDir, "report.csv")
		if err := report.ExportCSV(csvPath, assets); err != nil {
			logx.Log.Error().Err(err).Msg("Failed to write report.csv")
		}

		txtPath := filepath.Join(baseDir, "report.txt")
		if err := report.ExportTXT(txtPath, scanRec.Domain, ReportScanID, assets); err != nil {
			logx.Log.Error().Err(err).Msg("Failed to write report.txt")
		}

		htmlPath := filepath.Join(baseDir, "report.html")
		if err := report.ExportHTML(htmlPath, scanRec.Domain, ReportScanID, assets); err != nil {
			logx.Log.Error().Err(err).Msg("Failed to write report.html")
		}

		fmt.Printf("\nReports Compiled Successfully\n\n")
		fmt.Printf("Scan ID:        %s\n", ReportScanID)
		fmt.Printf("Target Domain:  %s\n", scanRec.Domain)
		fmt.Printf("Total Assets:   %d\n", len(assets))
		fmt.Printf("Reports saved in: %s/\n", baseDir)

		return nil
	},
}

func init() {
	reportCmd.Flags().StringVar(&ReportScanID, "scan-id", "", "scan ID of the session to report (required)")

	RootCmd.AddCommand(reportCmd)
}
