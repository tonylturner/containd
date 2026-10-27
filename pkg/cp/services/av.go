// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
	commonlog "github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

const (
	// DefaultClamdSocket is the clamd socket used when none is configured.
	DefaultClamdSocket = "/run/clamav/clamd.sock"
	// DefaultCustomDefsPath stores uploaded custom signature databases.
	DefaultCustomDefsPath = "/data/clamav/custom"
	defaultAVTimeout      = 5 * time.Second
	defaultAVCacheTTL     = 10 * time.Minute
	// avStatusProbeTimeout bounds the live readiness check in Status.
	avStatusProbeTimeout = 2 * time.Second
)

var (
	// ErrAVConflict reports an operation the applied AV configuration or the
	// current backend state does not allow.
	ErrAVConflict = errors.New("av operation not available")
	// ErrAVInvalid reports a rejected request, such as an invalid definition.
	ErrAVInvalid = errors.New("invalid av request")
	// ErrAVStopped reports use after the owning process stopped the manager.
	ErrAVStopped = errors.New("av manager stopped")
)

// AVOptions locate the engine-local ClamAV runtime.
type AVOptions struct {
	// StateDir holds the rendered clamd and FreshClam configurations.
	StateDir      string
	DatabaseDir   string
	ClamdPath     string
	FreshclamPath string
	ClamscanPath  string
	// DaemonUser runs clamd and owns FreshClam downloads when the engine is
	// root and the account exists.
	DaemonUser string
}

// DefaultAVOptions returns the image layout with binaries detected on disk.
func DefaultAVOptions() AVOptions {
	clamd, _ := detectBinary([]string{"/usr/sbin/clamd", "/usr/bin/clamd"})
	freshclam, _ := detectBinary([]string{"/usr/bin/freshclam", "/usr/sbin/freshclam"})
	clamscan, _ := detectBinary([]string{"/usr/bin/clamscan", "/usr/sbin/clamscan"})
	return AVOptions{
		StateDir:      "/run/containd/av",
		DatabaseDir:   "/var/lib/clamav",
		ClamdPath:     clamd,
		FreshclamPath: freshclam,
		ClamscanPath:  clamscan,
		DaemonUser:    "clamav",
	}
}

// AVManager is the engine's single antivirus owner: it applies AV settings,
// supervises clamd and the FreshClam schedule, manages custom definitions
// and scans complete objects. Its children live until Stop.
type AVManager struct {
	opts   AVOptions
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	// op serializes Apply, definition changes and post-update reloads. It is
	// a channel so goroutines being stopped can abandon the wait.
	op chan struct{}

	OnEvent func(kind string, attrs map[string]any)

	mu         sync.Mutex
	lastCfg    config.AVConfig
	lastRender time.Time
	lastError  string
	lastTest   time.Time
	defsGen    uint64
	clamd      clamdProcess
	fresh      freshclamState
	trust      avTrust
	scans      meter
	scanErrs   meter
	detections int
	cache      map[string]cachedVerdict
	maxCache   int

	slots        chan struct{}
	backendReady bool
	reloadError  string
	defsPath     string
	log          *zap.SugaredLogger
	// validateDef checks a candidate signature database before activation.
	validateDef func(ctx context.Context, path string) error
}

type cachedVerdict struct {
	result  avscan.Result
	expires time.Time
}

// NewAVManager returns a manager whose daemons and scans are bound to ctx
// and stopped by Stop.
func NewAVManager(ctx context.Context, opts AVOptions) *AVManager {
	ctx, cancel := context.WithCancel(ctx)
	m := &AVManager{
		opts:     opts,
		ctx:      ctx,
		cancel:   cancel,
		op:       make(chan struct{}, 1),
		cache:    make(map[string]cachedVerdict),
		maxCache: 1024,
		slots:    make(chan struct{}, 8),
		log:      newAVLogger(),
	}
	m.validateDef = m.clamscanValidate
	return m
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

// lock acquires the operation lock unless ctx or the manager ends first.
func (m *AVManager) lock(ctx context.Context) error {
	select {
	case m.op <- struct{}{}:
		if m.ctx.Err() != nil {
			<-m.op
			return ErrAVStopped
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-m.ctx.Done():
		return ErrAVStopped
	}
}

func (m *AVManager) unlock() { <-m.op }

// Stop ends the FreshClam schedule, stops clamd, and
// waits for every goroutine and child process the manager started.
func (m *AVManager) Stop() error {
	m.op <- struct{}{}
	defer m.unlock()
	m.stopFreshclam()
	err := m.stopClamd()
	m.cancel()
	m.mu.Lock()
	m.backendReady = false
	m.mu.Unlock()
	m.wg.Wait()
	metrics.ServicesRunning.WithLabelValues("av").Set(0)
	return err
}

// Apply makes cfg the running AV configuration. Settings that do not affect
// clamd or FreshClam leave them running. It returns an error when the
// configured backend is missing, cannot start or does not answer in time.
func (m *AVManager) Apply(ctx context.Context, cfg config.AVConfig) error {
	if err := m.lock(ctx); err != nil {
		return err
	}
	defer m.unlock()
	m.mu.Lock()
	m.lastCfg = cfg
	if !cfg.Enabled || avMode(cfg) != "clamav" {
		m.reloadError = ""
	}
	m.lastRender = time.Now().UTC()
	m.mu.Unlock()
	err := m.applyBackend(ctx, cfg)
	m.mu.Lock()
	if err != nil {
		m.lastError = err.Error()
		m.backendReady = false
	} else {
		m.lastError = ""
		m.backendReady = cfg.Enabled
	}
	m.mu.Unlock()
	ready := 0.0
	if cfg.Enabled && err == nil {
		ready = 1
	}
	metrics.ServicesRunning.WithLabelValues("av").Set(ready)
	m.emit("service.av.updated", map[string]any{
		"enabled": cfg.Enabled,
		"mode":    avMode(cfg),
	})
	return err
}

func (m *AVManager) applyBackend(ctx context.Context, cfg config.AVConfig) error {
	mode := avMode(cfg)
	if !cfg.Enabled || mode != "clamav" {
		m.stopFreshclam()
		if err := m.stopClamd(); err != nil {
			return err
		}
	}
	if !cfg.Enabled {
		return nil
	}
	switch mode {
	case "icap":
		return m.probeICAP(ctx, cfg)
	case "clamav":
		return m.applyClamAV(ctx, cfg)
	default:
		return fmt.Errorf("%w: unsupported av mode %q", ErrAVInvalid, mode)
	}
}

func (m *AVManager) probeICAP(ctx context.Context, cfg config.AVConfig) error {
	srv := firstICAPServer(cfg)
	err := m.icapClient(cfg).Probe(ctx, srv)
	m.mu.Lock()
	m.lastTest = time.Now().UTC()
	m.mu.Unlock()
	if err != nil {
		m.emit("service.av.icap_probe_failed", map[string]any{"address": srv.Address, "error": err.Error()})
		return fmt.Errorf("icap server %s: %w", srv.Address, err)
	}
	m.emit("service.av.icap_probe_ok", map[string]any{"address": srv.Address})
	return nil
}

func (m *AVManager) icapClient(cfg config.AVConfig) *ICAPClient {
	return &ICAPClient{Timeout: avTimeout(cfg), RootCAs: m.trustPool()}
}

// Current returns the applied configuration.
func (m *AVManager) Current() config.AVConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastCfg
}

// Status reports the applied settings, live backend readiness and counters.
func (m *AVManager) Status(ctx context.Context) map[string]any {
	m.mu.Lock()
	cfg := m.lastCfg
	out := meterStatus(&m.scans, &m.scanErrs)
	out["enabled"] = cfg.Enabled
	out["mode"] = avMode(cfg)
	out["failPolicy"] = firstNonEmpty(strings.ToLower(cfg.FailPolicy), "open")
	out["failOpenICS"] = cfg.FailOpenICS
	out["block_ttl"] = cfg.BlockTTL
	out["max_size"] = cfg.MaxSizeBytes
	out["timeout"] = int(avTimeout(cfg) / time.Second)
	out["cache_ttl"] = avCacheTTL(cfg).String()
	out["cache_size"] = len(m.cache)
	out["icap_servers"] = len(cfg.ICAP.Servers)
	out["detections"] = m.detections
	out["definitions_generation"] = m.defsGen
	out["clamav_socket"] = clamdSocket(cfg)
	out["clamav_path"] = m.opts.ClamdPath
	out["clamav_running"] = m.clamd.running()
	out["clamav_pid"] = m.clamd.pid()
	out["clamav_last_start"] = formatMaybe(m.clamd.lastStart)
	out["clamav_last_stop"] = formatMaybe(m.clamd.lastStop)
	out["clamav_last_exit"] = m.clamd.lastExit
	out["clamav_custom_defs"] = customDefsPath(cfg)
	out["freshclam_path"] = m.opts.FreshclamPath
	out["freshclam_enabled"] = cfg.ClamAV.FreshclamEnabled
	out["freshclam_interval"] = ""
	if interval, err := freshclamInterval(cfg.ClamAV); err == nil {
		out["freshclam_interval"] = interval.String()
	}
	out["freshclam_last"] = formatMaybe(m.fresh.last)
	out["freshclam_error"] = m.fresh.err
	out["freshclam_running"] = m.fresh.running
	out["freshclam_runs"] = m.fresh.runs
	out["last_render"] = formatMaybe(m.lastRender)
	out["last_error"] = m.lastError
	out["last_test"] = formatMaybe(m.lastTest)
	out["trust_revision"] = trustRevision(m.trust.bundle)
	m.mu.Unlock()

	ready, version, readyErr := m.readiness(ctx, cfg)
	m.mu.Lock()
	if m.reloadError != "" {
		ready, readyErr = false, m.reloadError
	}
	m.mu.Unlock()
	out["ready"] = ready
	out["db_version"] = version
	out["ready_error"] = readyErr
	return out
}

// readiness checks the backend live: clamd must answer PING and VERSION, an
// ICAP server must answer OPTIONS.
func (m *AVManager) readiness(ctx context.Context, cfg config.AVConfig) (bool, string, string) {
	if !cfg.Enabled {
		return false, "", "disabled"
	}
	ctx, cancel := context.WithTimeout(ctx, min(avTimeout(cfg), avStatusProbeTimeout))
	defer cancel()
	switch avMode(cfg) {
	case "clamav":
		client := &ClamAVClient{Timeout: avStatusProbeTimeout, Socket: clamdSocket(cfg)}
		if err := client.Ping(ctx); err != nil {
			return false, "", err.Error()
		}
		version, err := client.Version(ctx)
		if err != nil {
			return false, "", err.Error()
		}
		return true, version, ""
	case "icap":
		if err := m.icapClient(cfg).Probe(ctx, firstICAPServer(cfg)); err != nil {
			return false, "", err.Error()
		}
		return true, "", ""
	}
	return false, "", "unsupported mode"
}

func (m *AVManager) emit(kind string, attrs map[string]any) {
	if m == nil {
		return
	}
	m.log.Infow("av event", "kind", kind, "attrs", attrs)
	if m.OnEvent != nil {
		m.OnEvent(kind, attrs)
	}
}

// daemonAccount resolves the account clamd and FreshClam run as. It is empty
// unless the engine runs as root and the account exists.
func (m *AVManager) daemonAccount() (name string, uid, gid int, ok bool) {
	if os.Geteuid() != 0 || strings.TrimSpace(m.opts.DaemonUser) == "" {
		return "", 0, 0, false
	}
	u, err := user.Lookup(m.opts.DaemonUser)
	if err != nil {
		return "", 0, 0, false
	}
	uid, uerr := strconv.Atoi(u.Uid)
	gid, gerr := strconv.Atoi(u.Gid)
	if uerr != nil || gerr != nil {
		return "", 0, 0, false
	}
	return u.Username, uid, gid, true
}

func exitText(err error) string {
	if err == nil {
		return "ok"
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.String()
	}
	return err.Error()
}
