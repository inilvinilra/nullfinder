package scheduler

import (
	"context"
	"fmt"
	"strings"
	"time"

	"nullfinder/internal/alert"
	"nullfinder/internal/config"
	"nullfinder/internal/logx"
	"nullfinder/internal/scan"
	"nullfinder/internal/storage"
)

// Scheduler coordinates background automated scanning jobs.
type Scheduler struct {
	cfg       *config.Config
	outputDir string
}

// NewScheduler initializes the scheduler context.
func NewScheduler(cfg *config.Config, outputDir string) *Scheduler {
	return &Scheduler{cfg: cfg, outputDir: outputDir}
}

// Start launches scanning tickers for all configured domains in the background.
func (s *Scheduler) Start(ctx context.Context) {
	if !s.cfg.Scheduler.Enabled {
		return
	}

	logx.Log.Info().Msg("Starting NullFinder background scheduler...")

	for _, job := range s.cfg.Scheduler.Jobs {
		go s.runJobLoop(ctx, job)
	}
}

func (s *Scheduler) runJobLoop(ctx context.Context, job config.SchedulerJob) {
	dur, err := time.ParseDuration(job.Interval)
	if err != nil {
		logx.Log.Error().Err(err).Str("domain", job.Domain).Str("interval", job.Interval).Msg("Invalid scheduler job interval duration, skipping")
		return
	}

	logx.Log.Info().Str("domain", job.Domain).Str("interval", job.Interval).Msg("Scheduled background scan loop initialized")

	ticker := time.NewTicker(dur)
	defer ticker.Stop()

	// Initial scan trigger on launch
	s.executeScheduledScan(ctx, job)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.executeScheduledScan(ctx, job)
		}
	}
}

func (s *Scheduler) executeScheduledScan(ctx context.Context, job config.SchedulerJob) {
	logx.Log.Info().Str("domain", job.Domain).Msg("Scheduled scan triggered")

	// 1. Fetch previous scan assets from Bbolt (if any)
	db, err := storage.NewBoltDB(s.cfg.Storage.Path)
	var prevAssets []storage.AssetRecord
	var latestScanID string
	if err == nil {
		scans, err := db.ListScans()
		if err == nil {
			var latestScanTime time.Time
			for _, rec := range scans {
				if rec.Domain == job.Domain && rec.Timestamp.After(latestScanTime) {
					latestScanTime = rec.Timestamp
					latestScanID = rec.ScanID
				}
			}
		}
		if latestScanID != "" {
			prevAssets, _ = db.GetAssets(latestScanID)
		}
		db.Close()
	}

	// 2. Generate a new scan ID
	cleanDomain := strings.ReplaceAll(job.Domain, ".", "-")
	newScanID := fmt.Sprintf("sched-%s-%s", cleanDomain, time.Now().Format("2006-01-02-150405"))

	outDir := s.outputDir
	if outDir == "" {
		outDir = "results"
	}

	// 3. Execute the scan
	opts := scan.RunScanOptions{
		Domain:    job.Domain,
		Mode:      job.Mode,
		OutputDir: outDir,
		ScanID:    newScanID,
	}

	err = scan.RunScan(ctx, s.cfg, opts)
	if err != nil {
		logx.Log.Error().Err(err).Str("domain", job.Domain).Msg("Scheduled scan failed")
		return
	}

	// 4. Retrieve current assets from DB
	db, err = storage.NewBoltDB(s.cfg.Storage.Path)
	var currentAssets []storage.AssetRecord
	if err == nil {
		currentAssets, _ = db.GetAssets(newScanID)
		db.Close()
	}

	// 5. Compare and dispatch notifications
	if len(prevAssets) > 0 {
		newSubs, newPorts, newWeb := scan.CompareAssets(prevAssets, currentAssets)
		if len(newSubs) > 0 || len(newPorts) > 0 || len(newWeb) > 0 {
			logx.Log.Info().Str("domain", job.Domain).Int("new_subs", len(newSubs)).Int("new_ports", len(newPorts)).Msg("New scheduled scan findings detected! Dispatched alerts")
			_ = alert.SendAlert(s.cfg, job.Domain, newSubs, newPorts, newWeb)
		} else {
			logx.Log.Info().Str("domain", job.Domain).Msg("Scheduled scan complete, no new findings.")
		}
	} else {
		logx.Log.Info().Str("domain", job.Domain).Msg("First scheduled scan complete, base assets populated in DB.")
	}
}
