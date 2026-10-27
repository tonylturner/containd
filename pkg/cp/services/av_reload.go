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

const reloadProbeFile = "containd-reload-probe.ndb"

// reloadClamd proves that a complete database activation became visible.
// PING, VERSION and RELOADING cannot establish this for custom definitions.
// Callers hold m.op and have installed all databases before writing this probe.
func (m *AVManager) reloadClamd(ctx context.Context, cfg config.AVConfig) (err error) {
	ctx, cancel := context.WithTimeout(ctx, avTimeout(cfg))
	defer cancel()
	stop := context.AfterFunc(m.ctx, cancel)
	defer stop()
	defer func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if err != nil {
			// Do not use an unconfirmed database with an old cache namespace
			// after the bounded confirmation window has expired.
			m.reloadError = err.Error()
		} else {
			m.defsGen++
			m.defsPath = customDefsPath(cfg)
			m.reloadError = ""
			m.backendReady = true
		}
	}()

	if err := m.requireDefinitions(); err != nil {
		return err
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return fmt.Errorf("create reload probe: %w", err)
	}
	name := "Containd.Reload." + hex.EncodeToString(token)
	payload := []byte("containd database activation " + hex.EncodeToString(token))
	signature := fmt.Sprintf("%s:0:*:%s\n", name, hex.EncodeToString(payload))
	if err := writeFileAtomic(filepath.Join(m.opts.DatabaseDir, reloadProbeFile), []byte(signature), 0o644); err != nil {
		return fmt.Errorf("install reload probe: %w", err)
	}
	m.mu.Lock()
	running := m.clamd.running() && m.clamd.conf == m.renderClamdConf(cfg)
	m.mu.Unlock()
	client := &ClamAVClient{Timeout: avTimeout(cfg), Socket: clamdSocket(cfg)}
	if running {
		if err := client.Reload(ctx); err != nil {
			return fmt.Errorf("reload clamd: %w", err)
		}
	} else {
		if err := m.ensureClamd(cfg); err != nil {
			return err
		}
		if err := m.waitClamdReady(ctx, cfg); err != nil {
			return err
		}
	}
	ticker := time.NewTicker(clamdReadyPoll)
	defer ticker.Stop()
	var detail string
	for {
		result, scanErr := client.Scan(ctx, bytes.NewReader(payload), int64(len(payload)))
		if scanErr == nil && result.Verdict == "malware" &&
			strings.TrimSuffix(result.Signature, ".UNOFFICIAL") == name {
			return nil
		}
		detail = fmt.Sprintf("probe verdict=%q signature=%q error=%v", result.Verdict, result.Signature, scanErr)
		select {
		case <-ctx.Done():
			return fmt.Errorf("clamd reload completion unconfirmed: %w (%s)", ctx.Err(), detail)
		case <-ticker.C:
		}
	}
}
