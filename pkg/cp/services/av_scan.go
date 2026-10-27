// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// ScanTask represents content submitted for scanning.
type ScanTask struct {
	Hash     string // hash of content (e.g., sha256)
	Size     int64
	Proto    string
	Source   string
	Dest     string
	Metadata map[string]any
	Preview  []byte // payload sent to the scanner
	ICS      bool   // true when the content is ICS/OT related
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
	if cfg.Enabled {
		m.scans.add(time.Now(), 1)
	}
	m.mu.Unlock()
	if !cfg.Enabled {
		return ScanResult{Verdict: "disabled"}
	}
	mode := avMode(cfg)
	key := ""
	if task.Hash != "" {
		key = avCacheKey(cfg, gen, task.Hash)
		if res, ok := m.cachedVerdict(key); ok {
			return ScanResult{Verdict: res}
		}
	}
	if cfg.MaxSizeBytes > 0 && int64(len(task.Preview)) > cfg.MaxSizeBytes {
		return m.handleScanError(cfg, fmt.Errorf("payload of %d bytes exceeds maxSizeBytes %d", len(task.Preview), cfg.MaxSizeBytes), mode, task)
	}
	ctx, cancel := context.WithTimeout(ctx, avTimeout(cfg))
	defer cancel()
	var verdict, signature string
	switch mode {
	case "icap":
		res, err := m.icapClient(cfg).Scan(ctx, firstICAPServer(cfg), task.Preview)
		if err != nil {
			return m.handleScanError(cfg, err, mode, task)
		}
		verdict, signature = res.Verdict, res.Status
	case "clamav":
		res, err := (&ClamAVClient{Timeout: avTimeout(cfg), Socket: clamdSocket(cfg)}).Scan(ctx, task.Preview)
		if err != nil {
			return m.handleScanError(cfg, err, mode, task)
		}
		verdict, signature = res.Verdict, res.Signature
	default:
		return m.handleScanError(cfg, fmt.Errorf("unsupported av mode %q", mode), mode, task)
	}
	m.recordVerdict(key, avCacheTTL(cfg), verdict)
	if verdict == "malware" {
		// The verdict owner (OnVerdict) reports the detection and enforces it.
		m.mu.Lock()
		m.detections++
		m.mu.Unlock()
	}
	return ScanResult{Verdict: verdict, Signature: signature}
}

// handleScanError maps a scan failure to the configured fail policy:
// closed reports "error", open reports "bypass".
func (m *AVManager) handleScanError(cfg config.AVConfig, err error, mode string, task ScanTask) ScanResult {
	failPolicy := strings.ToLower(strings.TrimSpace(cfg.FailPolicy))
	if failPolicy == "" || (task.ICS && cfg.FailOpenICS) {
		failPolicy = "open"
	}
	m.mu.Lock()
	m.scanErrs.add(time.Now(), 1)
	m.lastError = err.Error()
	m.mu.Unlock()
	attrs := map[string]any{"error": err.Error(), "mode": mode}
	if task.Hash != "" {
		attrs["hash"] = task.Hash
	}
	m.emit("service.av.scan_error", attrs)
	if failPolicy == "closed" {
		m.emit("service.av.fail_closed", attrs)
		return ScanResult{Verdict: "error", Error: err}
	}
	m.emit("service.av.fail_open", attrs)
	return ScanResult{Verdict: "bypass", Error: err}
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

func avCacheTTL(cfg config.AVConfig) time.Duration {
	if cfg.CacheTTL > 0 {
		return cfg.CacheTTL
	}
	return defaultAVCacheTTL
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

func customDefsPath(cfg config.AVConfig) string {
	if p := strings.TrimSpace(cfg.ClamAV.CustomDefsPath); p != "" {
		return p
	}
	return DefaultCustomDefsPath
}

func (m *AVManager) cachedVerdict(key string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.cache[key]
	if !ok {
		return "", false
	}
	if v.expires.Before(time.Now()) {
		delete(m.cache, key)
		return "", false
	}
	return v.verdict, true
}

func (m *AVManager) recordVerdict(key string, ttl time.Duration, verdict string) {
	if key == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.cache) >= m.maxCache {
		// simple eviction: reset cache.
		m.cache = make(map[string]cachedVerdict)
	}
	m.cache[key] = cachedVerdict{verdict: verdict, expires: time.Now().Add(ttl)}
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

// StartWorker scans queued tasks until the manager stops.
func (m *AVManager) StartWorker() {
	if m == nil || m.queue == nil {
		return
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		for m.ctx.Err() == nil {
			task, ok := m.queue.Dequeue(500 * time.Millisecond)
			if !ok {
				continue
			}
			res := m.Scan(m.ctx, task)
			if m.OnVerdict != nil {
				m.OnVerdict(task, res)
			}
		}
	}()
}
