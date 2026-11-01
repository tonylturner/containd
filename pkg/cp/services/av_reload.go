// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package services

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

const (
	reloadProbeFile = "containd-reload-probe.ndb"
	// reloadConfirmTimeout bounds one attempt to observe an activated
	// database. A full reload of the official databases takes tens of
	// seconds on a small engine, far longer than any scan.
	reloadConfirmTimeout = 5 * time.Minute
	// reloadRetryMin and reloadRetryMax bound the backoff between retries of
	// a failed activation.
	reloadRetryMin = 30 * time.Second
	reloadRetryMax = 10 * time.Minute
	// reloadPollMax caps the interval between probe scans while confirming.
	reloadPollMax = 2 * time.Second
)

// reloadBounds are the activation timing bounds; tests shorten them.
type reloadBounds struct {
	confirm  time.Duration
	retryMin time.Duration
	retryMax time.Duration
}

func defaultReloadBounds() reloadBounds {
	return reloadBounds{confirm: reloadConfirmTimeout, retryMin: reloadRetryMin, retryMax: reloadRetryMax}
}

// pendingReload is one database activation awaiting proof. Confirmation runs
// in the background, so a caller's deadline never decides its outcome.
type pendingReload struct {
	cancel context.CancelFunc
	done   chan struct{}
	err    error // set before done is closed
}

// reloadProbe is the random signature whose detection proves an activation.
type reloadProbe struct {
	name    string
	payload []byte
}

// reloadClamd activates the installed databases: it writes a random probe
// signature, asks a running clamd to RELOAD (or starts clamd) and confirms
// the activation in the background within the confirmation window. PING,
// VERSION and RELOADING cannot establish that a custom definition is live.
// It returns an error only when the activation could not be started. Every
// failure records reloadError, which makes the backend not ready, and
// schedules a retry with bounded backoff. Callers hold m.op and have
// installed all databases before calling.
func (m *AVManager) reloadClamd(ctx context.Context, cfg config.AVConfig) error {
	m.cancelReload()
	probe, err := m.startReload(ctx, cfg)
	if err != nil {
		m.failReload(err)
		return err
	}
	confirmCtx, cancel := context.WithTimeout(m.ctx, m.reloadBounds().confirm)
	p := &pendingReload{cancel: cancel, done: make(chan struct{})}
	m.mu.Lock()
	m.reload = p
	m.mu.Unlock()
	m.wg.Add(1)
	go m.confirmReload(confirmCtx, p, cfg, probe)
	return nil
}

func (m *AVManager) startReload(ctx context.Context, cfg config.AVConfig) (reloadProbe, error) {
	if err := m.requireDefinitions(); err != nil {
		return reloadProbe{}, err
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return reloadProbe{}, fmt.Errorf("create reload probe: %w", err)
	}
	probe := reloadProbe{
		name:    "Containd.Reload." + hex.EncodeToString(token),
		payload: []byte("containd database activation " + hex.EncodeToString(token)),
	}
	signature := fmt.Sprintf("%s:0:*:%s\n", probe.name, hex.EncodeToString(probe.payload))
	if err := writeFileAtomic(filepath.Join(m.opts.DatabaseDir, reloadProbeFile), []byte(signature), 0o644); err != nil {
		return reloadProbe{}, fmt.Errorf("install reload probe: %w", err)
	}
	m.mu.Lock()
	running := m.clamd.running() && m.clamd.conf == m.renderClamdConf(cfg)
	m.mu.Unlock()
	if !running {
		if err := m.ensureClamd(cfg); err != nil {
			return reloadProbe{}, err
		}
		if err := m.waitClamdReady(ctx, cfg); err != nil {
			return reloadProbe{}, err
		}
		return probe, nil
	}
	cmdCtx, cancel := context.WithTimeout(ctx, avTimeout(cfg))
	defer cancel()
	client := &ClamAVClient{Timeout: avTimeout(cfg), Socket: clamdSocket(cfg)}
	if err := client.Reload(cmdCtx); err != nil {
		return reloadProbe{}, fmt.Errorf("reload clamd: %w", err)
	}
	return probe, nil
}

// confirmReload is the background confirmer for one activation. A newer
// activation or a clamd stop supersedes it, in which case it records
// nothing.
func (m *AVManager) confirmReload(ctx context.Context, p *pendingReload, cfg config.AVConfig, probe reloadProbe) {
	defer m.wg.Done()
	err := m.observeProbe(ctx, cfg, probe)
	p.cancel()
	m.mu.Lock()
	current := m.reload == p
	if current {
		m.reload = nil
		if err == nil {
			m.defsGen++
			m.defsPath = customDefsPath(cfg)
			if m.lastError == m.reloadError {
				m.lastError = ""
			}
			m.reloadError = ""
			m.reloadAttempt = 0
			m.refreshBackendLocked()
		}
	}
	gen := m.defsGen
	m.mu.Unlock()
	if current {
		p.err = err
	}
	close(p.done)
	switch {
	case !current:
	case err == nil:
		m.emit("service.av.clamav_reload_confirmed", map[string]any{"definitions_generation": gen})
	default:
		m.failReload(err)
	}
}

// observeProbe scans the probe payload until clamd detects it, clamd exits
// or ctx ends. Each scan has its own per-probe deadline.
func (m *AVManager) observeProbe(ctx context.Context, cfg config.AVConfig, probe reloadProbe) error {
	client := &ClamAVClient{Timeout: avTimeout(cfg), Socket: clamdSocket(cfg)}
	interval := clamdReadyPoll
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		m.mu.Lock()
		running, exit := m.clamd.running(), m.clamd.lastExit
		m.mu.Unlock()
		if !running {
			return fmt.Errorf("clamd exited before confirming the reload (%s)", exit)
		}
		scanCtx, cancel := context.WithTimeout(ctx, avTimeout(cfg))
		result, scanErr := client.Scan(scanCtx, bytes.NewReader(probe.payload), int64(len(probe.payload)))
		cancel()
		if scanErr == nil && result.Verdict == "malware" &&
			strings.TrimSuffix(result.Signature, ".UNOFFICIAL") == probe.name {
			return nil
		}
		detail := fmt.Sprintf("probe verdict=%q signature=%q error=%v", result.Verdict, result.Signature, scanErr)
		timer.Reset(interval)
		select {
		case <-ctx.Done():
			return fmt.Errorf("clamd reload completion unconfirmed: %w (%s)", ctx.Err(), detail)
		case <-timer.C:
		}
		interval = min(interval*2, reloadPollMax)
	}
}

// failReload records a failed activation and schedules its retry.
func (m *AVManager) failReload(err error) {
	bounds := m.reloadBounds()
	m.mu.Lock()
	m.reloadError = err.Error()
	delay := bounds.retryMin
	for i := 0; i < m.reloadAttempt && delay < bounds.retryMax; i++ {
		delay *= 2
	}
	delay = min(delay, bounds.retryMax)
	m.reloadAttempt++
	m.retrySeq++
	seq := m.retrySeq
	stopped := m.ctx.Err() != nil
	m.mu.Unlock()
	if stopped {
		return
	}
	m.emit("service.av.clamav_reload_failed", map[string]any{"error": err.Error(), "retry_in": delay.String()})
	m.wg.Add(1)
	go m.retryReload(seq, delay)
}

// retryReload re-runs the activation after delay unless it was resolved,
// superseded by a newer activation or a newer retry, or the manager stopped.
func (m *AVManager) retryReload(seq uint64, delay time.Duration) {
	defer m.wg.Done()
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-m.ctx.Done():
		return
	case <-timer.C:
	}
	if err := m.lock(m.ctx); err != nil {
		return
	}
	defer m.unlock()
	cfg := m.Current()
	m.mu.Lock()
	due := cfg.Enabled && avMode(cfg) == "clamav" && m.reloadError != "" && m.reload == nil && m.retrySeq == seq
	m.mu.Unlock()
	if !due {
		return
	}
	ctx, cancel := context.WithTimeout(m.ctx, m.reloadBounds().confirm)
	defer cancel()
	// A failure records itself and schedules the next retry.
	_ = m.reloadClamd(ctx, cfg)
}

// awaitReload waits for the pending activation until ctx ends. A caller
// whose deadline passes first gets nil: the activation continues in the
// background, Status reports it as pending and Ready stays truthful.
func (m *AVManager) awaitReload(ctx context.Context) error {
	m.mu.Lock()
	p := m.reload
	m.mu.Unlock()
	if p == nil {
		return nil
	}
	select {
	case <-p.done:
		return p.err
	case <-ctx.Done():
		return nil
	}
}

// cancelReload abandons a pending activation because a newer one supersedes
// it or clamd is stopping. Its waiters see no error.
func (m *AVManager) cancelReload() {
	m.mu.Lock()
	p := m.reload
	m.reload = nil
	m.mu.Unlock()
	if p != nil {
		p.cancel()
	}
}

func (m *AVManager) reloadBounds() reloadBounds {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bounds
}
