// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	commonlog "github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

const (
	// DefaultClamdSocket is the clamd socket used when none is configured.
	DefaultClamdSocket = "/run/clamav/clamd.sock"
	defaultAVTimeout   = 5 * time.Second
)

// AVManager handles antivirus configuration and async scan orchestration.
// It supports ICAP probing, async scan queueing, and optional ClamAV supervision.
type AVManager struct {
	mu         sync.Mutex
	lastCfg    config.AVConfig
	lastRender time.Time
	lastError  string
	lastTest   time.Time
	OnEvent    func(kind string, attrs map[string]any)
	OnVerdict  func(task ScanTask, res ScanResult)

	defsGen        uint64
	clamdPath      string
	clamdCmd       *exec.Cmd
	clamdDone      <-chan struct{}
	clamdLastStart time.Time
	clamdLastStop  time.Time
	clamdLastExit  string
	freshclamPath  string
	freshclamLast  time.Time
	freshclamErr   string
	customDefsPath string
	freshCancel    context.CancelFunc
	freshRunning   bool

	cache    map[string]cachedVerdict
	maxCache int

	queue *ScanQueue
	log   *zap.SugaredLogger
}

type cachedVerdict struct {
	verdict string
	expires time.Time
}

func NewAVManager() *AVManager {
	clamdPath, _ := detectBinary([]string{
		"/usr/sbin/clamd",
		"/usr/bin/clamd",
	})
	freshclamPath, _ := detectBinary([]string{
		"/usr/bin/freshclam",
		"/usr/sbin/freshclam",
	})
	return &AVManager{
		clamdPath:     clamdPath,
		freshclamPath: freshclamPath,
		cache:         make(map[string]cachedVerdict),
		maxCache:      1024,
		queue:         NewScanQueue(2048),
		log:           newAVLogger(),
	}
}

func newAVLogger() *zap.SugaredLogger {
	lg, err := commonlog.NewZap("av", "av", commonlog.Options{
		FilePath: "/data/logs/av.log",
		JSON:     true,
		Level:    "info",
	})
	if err != nil {
		return zap.NewNop().Sugar()
	}
	return lg
}

func (m *AVManager) Apply(ctx context.Context, cfg config.AVConfig) error {
	_ = ctx
	m.mu.Lock()
	m.lastCfg = cfg
	m.lastRender = time.Now().UTC()
	m.lastError = ""
	if m.freshCancel != nil {
		m.freshCancel()
		m.freshCancel = nil
	}
	if m.cache == nil {
		m.cache = make(map[string]cachedVerdict)
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 10 * time.Minute
	}
	// Default fail-open for ICS traffic unless explicitly disabled in future.
	if !cfg.FailOpenICS {
		cfg.FailOpenICS = true
	}
	if cfg.BlockTTL <= 0 {
		cfg.BlockTTL = 600
	}
	if strings.TrimSpace(cfg.ClamAV.CustomDefsPath) == "" {
		cfg.ClamAV.CustomDefsPath = "/data/clamav/custom"
	}
	m.customDefsPath = cfg.ClamAV.CustomDefsPath
	m.mu.Unlock()
	if cfg.Enabled {
		if err := m.probe(ctx, cfg); err != nil {
			return err
		}
	} else if err := m.stopClamd(); err != nil {
		return err
	}
	m.emit("service.av.updated", map[string]any{
		"enabled": cfg.Enabled,
		"mode":    strings.ToLower(cfg.Mode),
	})
	return nil
}

func (m *AVManager) Current() config.AVConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastCfg
}

func (m *AVManager) CustomDefsPath() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.TrimSpace(m.customDefsPath) != "" {
		return m.customDefsPath
	}
	return "/data/clamav/custom"
}

func (m *AVManager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	clamdRunning := m.clamdCmd != nil && m.clamdCmd.Process != nil
	clamdPID := 0
	if clamdRunning {
		clamdPID = m.clamdCmd.Process.Pid
	}
	return map[string]any{
		"enabled":     m.lastCfg.Enabled,
		"mode":        firstNonEmpty(strings.ToLower(m.lastCfg.Mode), "icap"),
		"failPolicy":  firstNonEmpty(strings.ToLower(m.lastCfg.FailPolicy), "open"),
		"failOpenICS": m.lastCfg.FailOpenICS,
		"block_ttl":   m.lastCfg.BlockTTL,
		"max_size":    m.lastCfg.MaxSizeBytes,
		"timeout":     m.lastCfg.TimeoutSec,
		"cache_ttl":   m.lastCfg.CacheTTL.String(),
		"cache_size":  len(m.cache),
		"queue_depth": func() int {
			if m.queue == nil {
				return 0
			}
			return m.queue.Len()
		}(),
		"icap_servers": func() int {
			if m.lastCfg.ICAP.Servers == nil {
				return 0
			}
			return len(m.lastCfg.ICAP.Servers)
		}(),
		"clamav_socket":      strings.TrimSpace(m.lastCfg.ClamAV.SocketPath),
		"clamav_path":        m.clamdPath,
		"clamav_running":     clamdRunning,
		"clamav_pid":         clamdPID,
		"clamav_last_start":  formatMaybe(m.clamdLastStart),
		"clamav_last_stop":   formatMaybe(m.clamdLastStop),
		"clamav_last_exit":   m.clamdLastExit,
		"clamav_custom_defs": m.customDefsPath,
		"freshclam_path":     m.freshclamPath,
		"freshclam_enabled":  m.lastCfg.ClamAV.FreshclamEnabled,
		"freshclam_interval": defaultFreshclamInterval(m.lastCfg.ClamAV.UpdateSchedule).String(),
		"freshclam_last":     formatMaybe(m.freshclamLast),
		"freshclam_error":    m.freshclamErr,
		"freshclam_running":  m.freshRunning,
		"last_render":        m.lastRender.Format(time.RFC3339Nano),
		"last_error":         m.lastError,
		"last_test":          formatMaybe(m.lastTest),
		"note":               "Scanning pipeline to be wired; this surfaces config/state now.",
	}
}

func (m *AVManager) emit(kind string, attrs map[string]any) {
	if m == nil || m.OnEvent == nil {
		return
	}
	m.OnEvent(kind, attrs)
	m.log.Infow("av event", "kind", kind, "attrs", attrs)
}

func (m *AVManager) probe(ctx context.Context, cfg config.AVConfig) error {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "icap"
	}
	switch mode {
	case "icap":
		m.testICAP(ctx, cfg.ICAP)
		return m.stopClamd()
	case "clamav":
		m.startClamd(ctx, cfg.ClamAV)
		m.startFreshclam(cfg.ClamAV)
	}
	return nil
}

func (m *AVManager) testICAP(ctx context.Context, cfg config.ICAPConfig) {
	if len(cfg.Servers) == 0 {
		return
	}
	srv := cfg.Servers[0]
	addr := strings.TrimSpace(srv.Address)
	if addr == "" {
		return
	}
	if err := (&ICAPClient{Timeout: avTimeout(m.Current())}).Probe(ctx, srv); err != nil {
		m.mu.Lock()
		m.lastError = err.Error()
		m.lastTest = time.Now().UTC()
		m.mu.Unlock()
		m.emit("service.av.icap_probe_failed", map[string]any{"address": addr, "error": err.Error()})
		return
	}
	m.mu.Lock()
	m.lastError = ""
	m.lastTest = time.Now().UTC()
	m.mu.Unlock()
	m.emit("service.av.icap_probe_ok", map[string]any{"address": addr})
}

// ScanTask represents a file or content that should be scanned.
type ScanTask struct {
	Hash     string // hash of content (e.g., sha256)
	Size     int64
	Proto    string
	Source   string
	Dest     string
	Metadata map[string]any
	Preview  []byte // optional limited payload for ICAP/ClamAV
	ICS      bool   // true when the content is ICS/OT related; forces fail-open
}

// ScanResult is the outcome of a scan.
type ScanResult struct {
	Verdict   string
	Signature string // backend detection name or ICAP status for malware
	Error     error
}

// Scan scans one task with the applied backend, using a verdict cached for
// the same content, backend and definitions generation when present.
func (m *AVManager) Scan(ctx context.Context, task ScanTask) ScanResult {
	if m == nil {
		return ScanResult{Verdict: "unknown", Error: fmt.Errorf("av manager nil")}
	}
	m.mu.Lock()
	cfg := m.lastCfg
	gen := m.defsGen
	m.mu.Unlock()
	if !cfg.Enabled {
		return ScanResult{Verdict: "disabled", Error: nil}
	}
	mode := avMode(cfg)
	key := ""
	if task.Hash != "" {
		key = avCacheKey(cfg, gen, task.Hash)
		if res, ok := m.cachedVerdict(key); ok {
			return ScanResult{Verdict: res, Error: nil}
		}
	}
	if cfg.MaxSizeBytes > 0 && int64(len(task.Preview)) > cfg.MaxSizeBytes {
		return m.handleScanError(fmt.Errorf("payload of %d bytes exceeds maxSizeBytes %d", len(task.Preview), cfg.MaxSizeBytes), mode, task)
	}
	ctx, cancel := context.WithTimeout(ctx, avTimeout(cfg))
	defer cancel()
	var (
		verdict   string
		signature string
	)
	switch mode {
	case "icap":
		res, err := (&ICAPClient{Timeout: avTimeout(cfg)}).Scan(ctx, firstICAPServer(cfg), task.Preview)
		if err != nil {
			return m.handleScanError(err, mode, task)
		}
		verdict, signature = res.Verdict, res.Status
	case "clamav":
		res, err := (&ClamAVClient{Timeout: avTimeout(cfg), Socket: clamdSocket(cfg)}).Scan(ctx, task.Preview)
		if err != nil {
			return m.handleScanError(err, mode, task)
		}
		verdict, signature = res.Verdict, res.Signature
	default:
		return m.handleScanError(fmt.Errorf("unsupported av mode %q", mode), mode, task)
	}
	m.recordVerdict(key, cfg.CacheTTL, verdict)
	if verdict == "malware" {
		m.emit("service.av.detected", map[string]any{
			"hash":      task.Hash,
			"proto":     task.Proto,
			"source":    task.Source,
			"dest":      task.Dest,
			"signature": signature,
		})
	}
	return ScanResult{Verdict: verdict, Signature: signature}
}

// avCacheKey binds a cached verdict to the backend that produced it and to
// the definitions generation it was produced with.
func avCacheKey(cfg config.AVConfig, gen uint64, hash string) string {
	backend := avMode(cfg)
	switch backend {
	case "icap":
		srv := firstICAPServer(cfg)
		backend += "|" + strings.TrimSpace(srv.Address) + "|" + strings.TrimSpace(srv.Service) + "|" + strconv.FormatBool(srv.UseTLS)
	case "clamav":
		backend += "|" + clamdSocket(cfg)
	}
	return backend + "|" + strconv.FormatUint(gen, 10) + "|" + hash
}

func avMode(cfg config.AVConfig) string {
	if mode := strings.ToLower(strings.TrimSpace(cfg.Mode)); mode != "" {
		return mode
	}
	return "icap"
}

// avTimeout is the per-scan and per-probe deadline; zero selects the default.
func avTimeout(cfg config.AVConfig) time.Duration {
	if cfg.TimeoutSec > 0 {
		return time.Duration(cfg.TimeoutSec) * time.Second
	}
	return defaultAVTimeout
}

func firstICAPServer(cfg config.AVConfig) config.ICAPServer {
	if len(cfg.ICAP.Servers) == 0 {
		return config.ICAPServer{}
	}
	return cfg.ICAP.Servers[0]
}

func clamdSocket(cfg config.AVConfig) string {
	if sock := strings.TrimSpace(cfg.ClamAV.SocketPath); sock != "" {
		return sock
	}
	return DefaultClamdSocket
}

func (m *AVManager) handleScanError(err error, mode string, task ScanTask) ScanResult {
	if err == nil {
		return ScanResult{Verdict: "error", Error: fmt.Errorf("scan error unknown")}
	}
	m.emit("service.av.scan_error", map[string]any{"error": err.Error(), "mode": mode, "error_count": 1})
	m.mu.Lock()
	failPolicy := strings.ToLower(strings.TrimSpace(m.lastCfg.FailPolicy))
	if failPolicy == "" {
		failPolicy = "open"
	}
	if task.ICS && m.lastCfg.FailOpenICS {
		failPolicy = "open"
	}
	m.lastError = err.Error()
	m.mu.Unlock()
	eventAttrs := map[string]any{
		"error": err.Error(),
		"mode":  mode,
	}
	if task.Hash != "" {
		eventAttrs["hash"] = task.Hash
	}
	switch failPolicy {
	case "closed":
		m.emit("service.av.fail_closed", eventAttrs)
		return ScanResult{Verdict: "error", Error: err}
	default:
		m.emit("service.av.fail_open", eventAttrs)
		return ScanResult{Verdict: "bypass", Error: err}
	}
}

func (m *AVManager) startFreshclam(cfg config.ClamAVConfig) {
	if !cfg.FreshclamEnabled {
		return
	}
	interval := defaultFreshclamInterval(cfg.UpdateSchedule)
	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.freshCancel = cancel
	m.mu.Unlock()
	// Run once immediately, then on interval.
	go m.runFreshclam(ctx, cfg)
	go m.runFreshclamLoop(ctx, cfg, interval)
}

func (m *AVManager) runFreshclamLoop(ctx context.Context, cfg config.ClamAVConfig, interval time.Duration) {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.runFreshclam(ctx, cfg)
		}
	}
}

func (m *AVManager) runFreshclam(ctx context.Context, cfg config.ClamAVConfig) {
	m.mu.Lock()
	path := m.freshclamPath
	if m.freshRunning {
		m.mu.Unlock()
		return
	}
	m.freshRunning = true
	m.mu.Unlock()
	if path == "" {
		m.mu.Lock()
		m.freshclamErr = "freshclam not present in image"
		m.freshRunning = false
		m.mu.Unlock()
		m.emit("service.av.freshclam_missing", map[string]any{})
		return
	}
	dataDir := "/var/lib/clamav"
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		m.mu.Lock()
		m.freshclamErr = err.Error()
		m.freshRunning = false
		m.mu.Unlock()
		m.emit("service.av.freshclam_failed", map[string]any{"error": err.Error()})
		return
	}
	if p := strings.TrimSpace(cfg.CustomDefsPath); p != "" {
		_ = os.MkdirAll(p, 0o755)
	}
	args := []string{"--datadir", dataDir, "--stdout", "--no-warnings"}
	if configPath := "/etc/clamav/freshclam.conf"; fileExists(configPath) {
		args = append(args, "--config-file", configPath)
	}
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		m.mu.Lock()
		m.freshclamErr = err.Error()
		m.freshRunning = false
		m.mu.Unlock()
		m.emit("service.av.freshclam_failed", map[string]any{"error": err.Error()})
		return
	}
	go func() {
		err := cmd.Wait()
		m.mu.Lock()
		m.freshRunning = false
		if err != nil {
			m.freshclamErr = err.Error()
		} else {
			m.freshclamErr = ""
			m.freshclamLast = time.Now().UTC()
			m.defsGen++
		}
		m.mu.Unlock()
		if err != nil {
			m.emit("service.av.freshclam_failed", map[string]any{"error": err.Error()})
			return
		}
		m.emit("service.av.freshclam_ok", map[string]any{"datadir": dataDir})
	}()
}

func defaultFreshclamInterval(s string) time.Duration {
	if strings.TrimSpace(s) == "" {
		return 6 * time.Hour
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return 6 * time.Hour
}

// RunFreshclamNow triggers a one-shot Freshclam run if enabled and not already running.
func (m *AVManager) RunFreshclamNow(ctx context.Context) error {
	if m == nil {
		return fmt.Errorf("av manager unavailable")
	}
	m.mu.Lock()
	cfg := m.lastCfg
	running := m.freshRunning
	m.mu.Unlock()
	if strings.ToLower(strings.TrimSpace(cfg.Mode)) != "clamav" {
		return fmt.Errorf("freshclam only available in clamav mode")
	}
	if !cfg.Enabled || !cfg.ClamAV.FreshclamEnabled {
		return fmt.Errorf("freshclam is disabled")
	}
	if running {
		return fmt.Errorf("freshclam already running")
	}
	go m.runFreshclam(ctx, cfg.ClamAV)
	return nil
}

func (m *AVManager) cachedVerdict(hash string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.cache[hash]
	if !ok {
		return "", false
	}
	if v.expires.Before(time.Now()) {
		delete(m.cache, hash)
		return "", false
	}
	return v.verdict, true
}

func (m *AVManager) recordVerdict(hash string, ttl time.Duration, verdict string) {
	if hash == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cache == nil {
		m.cache = make(map[string]cachedVerdict)
	}
	if len(m.cache) >= m.maxCache {
		// simple eviction: reset cache.
		m.cache = make(map[string]cachedVerdict)
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	m.cache[hash] = cachedVerdict{
		verdict: verdict,
		expires: time.Now().Add(ttl),
	}
}

// EnqueueScan adds a scan task to the queue (best-effort).
func (m *AVManager) EnqueueScan(task ScanTask) {
	if m == nil || m.queue == nil {
		return
	}
	if ok := m.queue.Enqueue(task); !ok {
		m.emit("service.av.queue_dropped", map[string]any{"hash": task.Hash})
	}
}

// StartWorker launches a background worker to process scan tasks asynchronously.
func (m *AVManager) StartWorker(ctx context.Context) {
	if m == nil || m.queue == nil {
		return
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			task, ok := m.queue.Dequeue(500 * time.Millisecond)
			if !ok {
				continue
			}
			res := m.Scan(ctx, task)
			if m.OnVerdict != nil {
				m.OnVerdict(task, res)
			}
		}
	}()
}

func (m *AVManager) startClamd(ctx context.Context, cfg config.ClamAVConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.clamdPath == "" {
		m.lastError = "clamd binary not found; supervision skipped"
		m.emit("service.av.clamav_missing", map[string]any{})
		return
	}
	if m.clamdCmd != nil && m.clamdCmd.Process != nil {
		// already running
		return
	}
	// Use background context so clamd outlives the API request that triggered it.
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(context.Background(), m.clamdPath, "--foreground=yes", fmt.Sprintf("--config-file=%s", "/etc/clamav/clamd.conf"))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		m.lastError = err.Error()
		m.emit("service.av.clamav_start_failed", map[string]any{"error": err.Error()})
		return
	}
	m.clamdCmd = cmd
	done := make(chan struct{})
	m.clamdDone = done
	m.lastError = ""
	m.clamdLastStart = time.Now().UTC()
	m.emit("service.av.clamav_started", map[string]any{"pid": cmd.Process.Pid})
	go func() {
		err := cmd.Wait()
		close(done)
		exit := "ok"
		if err != nil {
			exit = err.Error()
		}
		m.mu.Lock()
		if m.clamdCmd == cmd {
			m.clamdLastExit = exit
			m.clamdLastStop = time.Now().UTC()
			m.clamdCmd = nil
		}
		m.mu.Unlock()
		m.emit("service.av.clamav_exited", map[string]any{"exit": exit})
	}()
}

func (m *AVManager) stopClamd() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.clamdCmd != nil && m.clamdCmd.Process != nil {
		if err := stopManagedProcess(m.clamdCmd.Process, m.clamdDone); err != nil {
			m.lastError = err.Error()
			return err
		}
		m.clamdLastStop = time.Now().UTC()
		m.emit("service.av.clamav_stopped", map[string]any{"pid": m.clamdCmd.Process.Pid})
	}
	m.clamdCmd = nil
	return nil
}
