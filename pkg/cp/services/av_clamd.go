// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// clamdReadyPoll is the PING interval while waiting for a starting clamd.
const clamdReadyPoll = 100 * time.Millisecond

// clamdProcess is the supervised clamd child. Fields are guarded by
// AVManager.mu; done is closed by the single Wait owner.
type clamdProcess struct {
	cmd       *exec.Cmd
	done      chan struct{}
	conf      string // rendered configuration the child was started with
	lastStart time.Time
	lastStop  time.Time
	lastExit  string
}

func (p *clamdProcess) running() bool {
	if p.cmd == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *clamdProcess) pid() int {
	if !p.running() {
		return 0
	}
	return p.cmd.Process.Pid
}

func (m *AVManager) clamdConfPath() string {
	return filepath.Join(m.opts.StateDir, "clamd.conf")
}

// applyClamAV converges clamd and FreshClam on cfg and waits, until ctx
// ends, for clamd to answer PING.
func (m *AVManager) applyClamAV(ctx context.Context, cfg config.AVConfig) error {
	if m.opts.ClamdPath == "" {
		return errors.New("clamav mode: clamd is not installed in this engine image")
	}
	if _, err := freshclamInterval(cfg.ClamAV); err != nil {
		return err
	}
	if cfg.ClamAV.FreshclamEnabled && m.opts.FreshclamPath == "" {
		return errors.New("clamav mode: freshclam is not installed in this engine image")
	}
	if err := m.prepareDatabaseDir(); err != nil {
		return fmt.Errorf("prepare database directory: %w", err)
	}
	if err := m.prepareDir(filepath.Dir(clamdSocket(cfg))); err != nil {
		return fmt.Errorf("prepare clamd socket directory: %w", err)
	}
	// FreshClam must still be able to bootstrap a missing real database.
	if err := m.ensureFreshclam(cfg); err != nil {
		return err
	}
	m.mu.Lock()
	changed := !m.clamd.running() || m.clamd.conf != m.renderClamdConf(cfg) || m.defsPath != customDefsPath(cfg) || m.reloadError != ""
	m.mu.Unlock()
	if changed {
		if _, err := m.activateDefinitions(ctx, cfg); err != nil {
			return err
		}
	}
	return m.waitClamdReady(ctx, cfg)
}

// ensureClamd starts clamd, restarting it only when its rendered
// configuration changed or it is not running.
func (m *AVManager) ensureClamd(cfg config.AVConfig) error {
	conf := m.renderClamdConf(cfg)
	m.mu.Lock()
	unchanged := m.clamd.running() && m.clamd.conf == conf
	m.mu.Unlock()
	if unchanged {
		return nil
	}
	// A synthetic reload probe is not an antivirus database on its own.
	// Without this check, a new installation could report every object clean
	// while FreshClam has not downloaded any actual definitions yet.
	if err := m.requireDefinitions(); err != nil {
		return err
	}
	if err := os.MkdirAll(m.opts.StateDir, 0o755); err != nil {
		return fmt.Errorf("prepare av state directory: %w", err)
	}
	if err := publishDaemonFiles(m.ctx, daemonFile{path: m.clamdConfPath(), body: []byte(conf)}); err != nil {
		return fmt.Errorf("write clamd config: %w", err)
	}
	if err := m.stopClamd(); err != nil {
		return err
	}
	return m.startClamd(conf)
}

func (m *AVManager) requireDefinitions() error {
	entries, err := os.ReadDir(m.opts.DatabaseDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == reloadProbeFile || !entry.Type().IsRegular() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".cvd" && ext != ".cld" && !slices.Contains(customDefExtensions, ext) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > 0 {
			return nil
		}
	}
	return errors.New("clamd: a signature database is required (reload probe excluded)")
}

func (m *AVManager) startClamd(conf string) error {
	if m.ctx.Err() != nil {
		return ErrAVStopped
	}
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(m.ctx, m.opts.ClamdPath, "--config-file="+m.clamdConfPath())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Engine shutdown asks clamd to exit cleanly before Go kills it.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		m.emit("service.av.clamav_start_failed", map[string]any{"error": err.Error()})
		return fmt.Errorf("start clamd: %w", err)
	}
	done := make(chan struct{})
	m.mu.Lock()
	m.clamd.cmd = cmd
	m.clamd.done = done
	m.clamd.conf = conf
	m.clamd.lastStart = time.Now().UTC()
	m.clamd.lastExit = ""
	m.mu.Unlock()
	m.emit("service.av.clamav_started", map[string]any{"pid": cmd.Process.Pid})
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		exit := exitText(cmd.Wait())
		close(done)
		m.mu.Lock()
		if m.clamd.cmd == cmd {
			m.clamd.lastExit = exit
			m.clamd.lastStop = time.Now().UTC()
		}
		m.mu.Unlock()
		m.emit("service.av.clamav_exited", map[string]any{"exit": exit})
	}()
	return nil
}

// stopClamd stops the supervised clamd and waits until it is reaped. An
// activation it was confirming is abandoned with it.
func (m *AVManager) stopClamd() error {
	m.cancelReload()
	m.mu.Lock()
	cmd, done := m.clamd.cmd, m.clamd.done
	m.mu.Unlock()
	if cmd == nil {
		return nil
	}
	if err := stopManagedProcess(cmd.Process, done); err != nil {
		return fmt.Errorf("stop clamd: %w", err)
	}
	m.mu.Lock()
	if m.clamd.cmd == cmd {
		m.clamd.cmd = nil
		m.clamd.conf = ""
		m.clamd.lastStop = time.Now().UTC()
	}
	m.mu.Unlock()
	m.emit("service.av.clamav_stopped", map[string]any{"pid": cmd.Process.Pid})
	return nil
}

// waitClamdReady polls PING until clamd answers, exits or ctx ends. Each
// PING has its own probe deadline so a hung clamd cannot stall one attempt
// for the whole of a long ctx.
func (m *AVManager) waitClamdReady(ctx context.Context, cfg config.AVConfig) error {
	client := &ClamAVClient{Timeout: avStatusProbeTimeout, Socket: clamdSocket(cfg)}
	ticker := time.NewTicker(clamdReadyPoll)
	defer ticker.Stop()
	for {
		pingCtx, cancel := context.WithTimeout(ctx, avStatusProbeTimeout)
		err := client.Ping(pingCtx)
		cancel()
		if err == nil {
			return nil
		}
		m.mu.Lock()
		running, exit := m.clamd.running(), m.clamd.lastExit
		m.mu.Unlock()
		if !running {
			return fmt.Errorf("clamd exited before becoming ready (%s); a signature database is required", exit)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("clamd not ready: %w", err)
		case <-ticker.C:
		}
	}
}
