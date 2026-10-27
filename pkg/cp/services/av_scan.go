// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package services

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
	"github.com/tonylturner/containd/pkg/cp/config"
)

var _ avscan.Scanner = (*AVManager)(nil)

// Ready returns the last applied backend state without network I/O. Live
// diagnostics, including PING/VERSION or OPTIONS, are available via Status.
func (m *AVManager) Ready() (bool, string) {
	if m == nil {
		return false, "av manager nil"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case m.ctx.Err() != nil:
		return false, ErrAVStopped.Error()
	case !m.lastCfg.Enabled:
		return false, "disabled"
	case m.reloadError != "":
		return false, m.reloadError
	case !m.backendReady:
		return false, firstNonEmpty(m.lastError, "backend not ready")
	case avMode(m.lastCfg) == "clamav" && !m.clamd.running():
		return false, "clamd not running"
	}
	return true, ""
}

// Scan sends a complete held object to the configured backend. Policy belongs
// to the gate; errors never become clean or bypass verdicts here.
func (m *AVManager) Scan(ctx context.Context, obj avscan.Object) avscan.Result {
	if m == nil {
		return avscan.Result{Verdict: avscan.Unscanned, Reason: avscan.ReasonNotReady, Detail: "av manager nil"}
	}
	m.mu.Lock()
	cfg := m.lastCfg
	m.mu.Unlock()
	backend := avBackend(cfg)
	unscanned := func(reason avscan.Reason, detail string) avscan.Result {
		return avscan.Result{Verdict: avscan.Unscanned, Reason: reason, Backend: backend, Detail: detail}
	}
	if !cfg.Enabled || m.ctx.Err() != nil {
		return unscanned(avscan.ReasonNotReady, "scanner disabled or stopped")
	}
	// Eligibility precedes both cache lookup and backend admission.
	if cfg.MaxSizeBytes > 0 && obj.Size > cfg.MaxSizeBytes {
		return unscanned(avscan.ReasonOversized, "object exceeds maxSizeBytes")
	}
	if obj.Size < 0 || obj.Body == nil {
		return unscanned(avscan.ReasonScannerError, "invalid object body or size")
	}
	select {
	case <-ctx.Done():
		return unscanned(avscan.ReasonBusy, ctx.Err().Error())
	case <-m.ctx.Done():
		return unscanned(avscan.ReasonNotReady, ErrAVStopped.Error())
	case m.slots <- struct{}{}:
	}
	defer func() { <-m.slots }()
	if ctx.Err() != nil {
		return unscanned(avscan.ReasonBusy, ctx.Err().Error())
	}
	m.mu.Lock()
	gen, reloadError := m.defsGen, m.reloadError
	m.scans.add(time.Now(), 1)
	m.mu.Unlock()
	if reloadError != "" {
		return unscanned(avscan.ReasonNotReady, reloadError)
	}
	key := ""
	if obj.SHA256 != "" {
		key = avCacheKey(cfg, gen, obj.SHA256)
		if res, ok := m.cachedVerdict(key); ok {
			return res
		}
	}
	ctx, cancel := context.WithTimeout(ctx, avTimeout(cfg))
	stop := context.AfterFunc(m.ctx, cancel)
	defer func() { stop(); cancel() }()
	body := io.NewSectionReader(obj.Body, 0, obj.Size)
	var verdict, signature string
	var err error
	switch avMode(cfg) {
	case "clamav":
		var res ClamdVerdict
		res, err = (&ClamAVClient{Timeout: avTimeout(cfg), Socket: clamdSocket(cfg)}).Scan(ctx, body, obj.Size)
		verdict, signature = res.Verdict, res.Signature
	case "icap":
		// Transitional adapter: the ICAP backend currently accepts bytes only.
		var payload []byte
		payload, err = io.ReadAll(body)
		if err == nil && int64(len(payload)) != obj.Size {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			var res ICAPVerdict
			res, err = m.icapClient(cfg).Scan(ctx, firstICAPServer(cfg), payload)
			verdict, signature = res.Verdict, res.Status
		}
	default:
		err = fmt.Errorf("unsupported av mode %q", avMode(cfg))
	}
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		reason := avscan.ReasonScannerError
		var ne net.Error
		switch {
		case errors.Is(err, errClamdOversized):
			reason = avscan.ReasonOversized
		case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() || errors.Is(ctx.Err(), context.DeadlineExceeded):
			reason = avscan.ReasonTimeout
		}
		m.mu.Lock()
		m.scanErrs.add(time.Now(), 1)
		m.lastError = err.Error()
		m.mu.Unlock()
		return unscanned(reason, err.Error())
	}
	res := avscan.Result{Backend: backend, Signature: signature}
	switch verdict {
	case "clean":
		res.Verdict = avscan.Clean
		res.Signature = ""
	case "malware":
		res.Verdict = avscan.Infected
		m.mu.Lock()
		m.detections++
		m.mu.Unlock()
	default:
		return unscanned(avscan.ReasonScannerError, "unrecognized backend verdict")
	}
	m.recordVerdict(key, avCacheTTL(cfg), res)
	return res
}

func avBackend(cfg config.AVConfig) string {
	backend := avMode(cfg)
	if backend == "icap" {
		srv := firstICAPServer(cfg)
		backend += "|" + strings.TrimSpace(srv.Address) + "|" + strings.TrimSpace(srv.Service) + "|" + strconv.FormatBool(srv.UseTLS)
	}
	return backend
}

func avCacheKey(cfg config.AVConfig, gen uint64, hash string) string {
	backend := avBackend(cfg)
	if avMode(cfg) == "clamav" {
		backend += "|" + clamdSocket(cfg)
	}
	return backend + "|" + strconv.FormatUint(gen, 10) + "|" + strconv.FormatInt(cfg.MaxSizeBytes, 10) + "|" + hash
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

func (m *AVManager) cachedVerdict(key string) (avscan.Result, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.cache[key]
	if !ok {
		return avscan.Result{}, false
	}
	if v.expires.Before(time.Now()) {
		delete(m.cache, key)
		return avscan.Result{}, false
	}
	return v.result, true
}

func (m *AVManager) recordVerdict(key string, ttl time.Duration, result avscan.Result) {
	if key == "" || (result.Verdict != avscan.Clean && result.Verdict != avscan.Infected) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.cache) >= m.maxCache {
		m.cache = make(map[string]cachedVerdict)
	}
	m.cache[key] = cachedVerdict{result: result, expires: time.Now().Add(ttl)}
}
