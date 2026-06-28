package api

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"nullfinder/internal/config"
	"nullfinder/internal/logx"
	"nullfinder/internal/scan"
	"nullfinder/internal/scheduler"
	"nullfinder/internal/storage"
)

//go:embed assets/index.html
var dashboardHTML []byte

// ScanStatus represents the lifecycle phase of an active scanning process.
type ScanStatus string

const (
	StatusRunning   ScanStatus = "running"
	StatusCompleted ScanStatus = "completed"
	StatusFailed    ScanStatus = "failed"
)

// ScanJob represents an in-memory active background scan.
type ScanJob struct {
	ScanID    string     `json:"scan_id"`
	Domain    string     `json:"domain"`
	Mode      string     `json:"mode"`
	Status    ScanStatus `json:"status"`
	Error     string     `json:"error,omitempty"`
	StartedAt time.Time  `json:"started_at"`
}

// ScanManager manages active scanning processes concurrently.
type ScanManager struct {
	sync.RWMutex
	jobs map[string]*ScanJob
}

// NewScanManager initializes an empty scan manager.
func NewScanManager() *ScanManager {
	return &ScanManager{
		jobs: make(map[string]*ScanJob),
	}
}

// AddJob registers a new running job.
func (sm *ScanManager) AddJob(job *ScanJob) {
	sm.Lock()
	defer sm.Unlock()
	sm.jobs[job.ScanID] = job
}

// GetJob returns a job by ID.
func (sm *ScanManager) GetJob(scanID string) (*ScanJob, bool) {
	sm.RLock()
	defer sm.RUnlock()
	job, exists := sm.jobs[scanID]
	return job, exists
}

// UpdateJobStatus updates the status of a job.
func (sm *ScanManager) UpdateJobStatus(scanID string, status ScanStatus, errMsg string) {
	sm.Lock()
	defer sm.Unlock()
	if job, exists := sm.jobs[scanID]; exists {
		job.Status = status
		job.Error = errMsg
	}
}

// ListJobs returns all active jobs.
func (sm *ScanManager) ListJobs() []*ScanJob {
	sm.RLock()
	defer sm.RUnlock()
	var list []*ScanJob
	for _, j := range sm.jobs {
		list = append(list, j)
	}
	return list
}

// DeleteJob removes a job from tracking.
func (sm *ScanManager) DeleteJob(scanID string) {
	sm.Lock()
	defer sm.Unlock()
	delete(sm.jobs, scanID)
}

// APIServer serves HTTP endpoints and static assets.
type APIServer struct {
	host      string
	port      int
	cfg       *config.Config
	manager   *ScanManager
	outputDir string
}

// NewServer initializes the APIServer.
func NewServer(host string, port int, cfg *config.Config, outputDir string) *APIServer {
	return &APIServer{
		host:      host,
		port:      port,
		cfg:       cfg,
		manager:   NewScanManager(),
		outputDir: outputDir,
	}
}

// Start launches the HTTP listening loop.
func (s *APIServer) Start() error {
	mux := http.NewServeMux()

	// Register Handlers
	mux.HandleFunc("/", s.handleDashboard)
	mux.HandleFunc("/api/scans", s.handleScans)
	mux.HandleFunc("/api/scans/", s.handleScanDetail)

	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	logx.Log.Info().Str("addr", addr).Msg("Starting NullFinder REST API & Web Dashboard Server")

	// Start background scheduler daemon
	sched := scheduler.NewScheduler(s.cfg, s.outputDir)
	sched.Start(context.Background())

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	return server.ListenAndServe()
}

// handleDashboard serves the embedded HTML interface.
func (s *APIServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(dashboardHTML)
}

// handleScans handles GET (list) and POST (trigger) scan operations.
func (s *APIServer) handleScans(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.listScans(w, r)
		return
	}
	if r.Method == http.MethodPost {
		s.triggerScan(w, r)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// listScans returns scans from database and active memory jobs.
func (s *APIServer) listScans(w http.ResponseWriter, r *http.Request) {
	db, err := storage.NewBoltDB(s.cfg.Storage.Path)
	var records []storage.ScanRecord
	if err == nil {
		records, _ = db.ListScans()
		db.Close()
	}

	// Format output
	type ScanResponse struct {
		ScanID    string    `json:"scan_id"`
		Domain    string    `json:"domain"`
		Mode      string    `json:"mode"`
		Status    string    `json:"status"`
		Timestamp time.Time `json:"timestamp,omitempty"`
		StartedAt time.Time `json:"started_at,omitempty"`
	}

	resMap := make(map[string]ScanResponse)

	// Add database records
	for _, rec := range records {
		resMap[rec.ScanID] = ScanResponse{
			ScanID:    rec.ScanID,
			Domain:    rec.Domain,
			Mode:      rec.Mode,
			Status:    "completed",
			Timestamp: rec.Timestamp,
		}
	}

	// Overlay/insert running jobs
	activeJobs := s.manager.ListJobs()
	for _, job := range activeJobs {
		resMap[job.ScanID] = ScanResponse{
			ScanID:    job.ScanID,
			Domain:    job.Domain,
			Mode:      job.Mode,
			Status:    string(job.Status),
			StartedAt: job.StartedAt,
		}
	}

	var responseList []ScanResponse
	for _, v := range resMap {
		responseList = append(responseList, v)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(responseList)
}

// triggerScan triggers a scan in a background goroutine.
func (s *APIServer) triggerScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		Mode   string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request payload", http.StatusBadRequest)
		return
	}

	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		http.Error(w, "Target domain must be specified", http.StatusBadRequest)
		return
	}

	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "hybrid"
	}

	// Generate scan ID
	cleanDomain := strings.ReplaceAll(domain, ".", "-")
	scanID := fmt.Sprintf("%s-%s", cleanDomain, time.Now().Format("2006-01-02-150405"))

	// Create running job
	job := &ScanJob{
		ScanID:    scanID,
		Domain:    domain,
		Mode:      mode,
		Status:    StatusRunning,
		StartedAt: time.Now(),
	}

	s.manager.AddJob(job)

	// Run scan in background
	go func() {
		outDir := s.outputDir
		if outDir == "" {
			outDir = "results"
		}
		opts := scan.RunScanOptions{
			Domain:    domain,
			Mode:      mode,
			OutputDir: outDir,
			ScanID:    scanID,
		}
		err := scan.RunScan(context.Background(), s.cfg, opts)
		if err != nil {
			logx.Log.Error().Err(err).Str("scan_id", scanID).Msg("Background scan execution failed")
			s.manager.UpdateJobStatus(scanID, StatusFailed, err.Error())
		} else {
			s.manager.UpdateJobStatus(scanID, StatusCompleted, "")
			// Delete the memory job tracker once completed so it doesn't linger indefinitely,
			// or keep it but mark it completed. Here we mark it completed so the active polling fetches the end status.
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(job)
}

// handleScanDetail handles GET (fetch findings) and DELETE scan operations.
func (s *APIServer) handleScanDetail(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid scan ID path", http.StatusBadRequest)
		return
	}
	scanID := parts[3]

	if r.Method == http.MethodGet {
		s.getScanDetail(w, r, scanID)
		return
	}
	if r.Method == http.MethodDelete {
		s.deleteScan(w, r, scanID)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// getScanDetail returns metadata and discovered assets for a scan ID.
func (s *APIServer) getScanDetail(w http.ResponseWriter, r *http.Request, scanID string) {
	db, err := storage.NewBoltDB(s.cfg.Storage.Path)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	scanRecord, err := db.GetScan(scanID)
	if err != nil {
		// Fallback: check if it's currently running in memory
		if job, exists := s.manager.GetJob(scanID); exists {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"scan_id":    job.ScanID,
				"domain":     job.Domain,
				"mode":       job.Mode,
				"status":     job.Status,
				"started_at": job.StartedAt,
				"assets":     []interface{}{},
			})
			return
		}
		http.NotFound(w, r)
		return
	}

	assets, _ := db.GetAssets(scanID)

	response := map[string]interface{}{
		"scan_id":   scanRecord.ScanID,
		"domain":    scanRecord.Domain,
		"mode":      scanRecord.Mode,
		"timestamp": scanRecord.Timestamp,
		"status":    "completed",
		"assets":    assets,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// deleteScan deletes the scan session.
func (s *APIServer) deleteScan(w http.ResponseWriter, r *http.Request, scanID string) {
	db, err := storage.NewBoltDB(s.cfg.Storage.Path)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	_ = db.DeleteScan(scanID)
	s.manager.DeleteJob(scanID)

	w.WriteHeader(http.StatusNoContent)
}
