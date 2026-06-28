package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"nullfinder/internal/api"
	"nullfinder/internal/logx"
)

var (
	ServeHost string
	ServePort int
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the REST API and Web Dashboard server",
	Long: `Starts the NullFinder service daemon, exposing REST API endpoints to run and query scans,
and hosts the premium dark-mode web dashboard UI at http://<host>:<port>/`,
	RunE: func(cmd *cobra.Command, args []string) error {
		srv := api.NewServer(ServeHost, ServePort, Cfg, OutputDir)
		logx.Log.Info().Str("host", ServeHost).Int("port", ServePort).Msg("Starting NullFinder daemon...")
		fmt.Printf("\nNullFinder Web Dashboard & API listening on http://%s:%d/\n", ServeHost, ServePort)
		return srv.Start()
	},
}

func init() {
	serveCmd.Flags().StringVar(&ServeHost, "host", "127.0.0.1", "interface address to bind the server to")
	serveCmd.Flags().IntVar(&ServePort, "port", 8080, "TCP port to listen on")

	RootCmd.AddCommand(serveCmd)
}
