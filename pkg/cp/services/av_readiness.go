// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package services

import (
	"context"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// One cheap local PING/VERSION or remote OPTIONS per second keeps a dead
// backend from leaving protection green. The shared two-second probe cap
// bounds a fresh observation to three seconds. Allowing an already-running
// probe to finish gives a conservative five-second loss/recovery bound,
// without tying network I/O to the gate's 200 ms observation loop.
const avObserveInterval = time.Second

// startObserver and stopObserver require op. Even a failed apply starts an
// observer so a backend that comes up late can recover without another apply.
func (m *AVManager) startObserver(cfg config.AVConfig, epoch uint64) {
	if !cfg.Enabled || (avMode(cfg) != "icap" && avMode(cfg) != "clamav") {
		return
	}
	ctx, cancel := context.WithCancel(m.ctx)
	done := make(chan struct{})
	m.observeCancel, m.observeDone = cancel, done
	go func() {
		defer close(done)
		timer := time.NewTimer(avObserveInterval)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				ready, _, why := m.readiness(ctx, cfg)
				if ctx.Err() != nil {
					return
				}
				m.publishBackend(epoch, ready, why)
				timer.Reset(avObserveInterval)
			}
		}
	}()
}

func (m *AVManager) stopObserver() {
	if m.observeCancel != nil {
		m.observeCancel()
		<-m.observeDone
		m.observeCancel, m.observeDone = nil, nil
	}
}

// publishBackend fences probes and scans from a superseded configuration.
// Reload proof errors remain a separate readiness constraint.
func (m *AVManager) publishBackend(epoch uint64, ready bool, why string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if epoch != m.backendEpoch || m.ctx.Err() != nil {
		return
	}
	m.backendReady, m.backendError = ready, why
	m.lastTest = time.Now().UTC()
}
