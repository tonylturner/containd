// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
	"github.com/tonylturner/containd/pkg/cp/config"
)

const (
	avObserveInterval = time.Second
	avOptionsTTLCap   = 30 * time.Second
)

// A complete protocol reply proves transport liveness, even when it cannot
// produce a scan verdict. Such failures must not erase OPTIONS capability.
var errScanProtocol = errors.New("backend scan protocol failure")

type avDirectionHealth struct {
	capable         bool
	healthy         bool
	capabilityError string
	scanError       string
	scanSeq         uint64
}

func sameAVBackend(a, b config.AVConfig) bool {
	return a.Enabled == b.Enabled && avBackend(a) == avBackend(b) &&
		(avMode(b) != "clamav" || clamdSocket(a) == clamdSocket(b))
}

func scanDirections(cfg config.AVConfig) []avscan.Direction {
	var dirs []avscan.Direction
	if cfg.HTTPUpload {
		dirs = append(dirs, avscan.Upload)
	}
	if cfg.HTTPDownload {
		dirs = append(dirs, avscan.Download)
	}
	return dirs
}

// configureDirectionsLocked preserves proof for retained directions. Newly
// selected directions need both capability and an initial scan-path canary.
func (m *AVManager) configureDirectionsLocked(cfg config.AVConfig) {
	next := make(map[avscan.Direction]avDirectionHealth)
	for _, dir := range scanDirections(cfg) {
		next[dir] = m.directions[dir]
	}
	m.directions = next
}

func (m *AVManager) nextProbeLocked() uint64 {
	m.probeSeq++
	return m.probeSeq
}

// Ordering is per independent fact: OPTIONS cannot supersede scan proof,
// nor can an unrelated direction's result discard a capability observation.
func (m *AVManager) currentProbeLocked(epoch uint64) bool {
	return epoch == m.backendEpoch && m.ctx.Err() == nil
}

// refreshBackendLocked is the sole reducer of capability and scan proof.
// Reload confirmation remains an independent readiness constraint.
func (m *AVManager) refreshBackendLocked() {
	m.backendReady, m.backendError = false, m.capabilityError
	if !m.lastCfg.Enabled {
		m.backendError = "disabled"
		return
	}
	if m.backendError != "" {
		return
	}
	for _, dir := range scanDirections(m.lastCfg) {
		state := m.directions[dir]
		if !state.capable {
			m.backendError = firstNonEmpty(state.capabilityError, string(dir)+" capability unconfirmed")
			return
		}
		if !state.healthy {
			m.backendError = firstNonEmpty(state.scanError, string(dir)+" scan path unconfirmed")
			return
		}
	}
	m.backendReady = true
}

// publishScan updates only this direction's scan proof. A transport failure
// additionally invalidates capability; successful scans cannot restore it.
func (m *AVManager) publishScan(epoch, seq uint64, dir avscan.Direction, healthy, transportFailure bool, why string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.currentProbeLocked(epoch) {
		return
	}
	wasReady := m.backendReady
	if transportFailure && seq >= m.capabilitySeq {
		m.capabilitySeq = seq
		m.capabilityError = why
		m.nextOptions = time.Time{}
		for d, state := range m.directions {
			state.capable = false
			state.capabilityError = why
			m.directions[d] = state
		}
	}
	if state, ok := m.directions[dir]; ok && seq >= state.scanSeq {
		state.scanSeq = seq
		// Only a canary can clear an established scan-path failure. A clean
		// ordinary object could equally be the result of antivirus bypass.
		if !healthy {
			state.healthy, state.scanError = false, why
		}
		m.directions[dir] = state
	}
	m.lastTest = time.Now().UTC()
	m.refreshBackendLocked()
	if wasReady && !m.backendReady {
		m.wakeObserverLocked()
	}
}

func (m *AVManager) wakeObserverLocked() {
	if m.observeWake != nil {
		select {
		case m.observeWake <- struct{}{}:
		default:
		}
	}
}

// observeBackend reserves a start sequence before I/O. The entire observation
// (capability plus any canaries) shares one two-second budget. Request-scoped
// cancellation is diagnostic only; expiry of our own budget is authoritative.
func (m *AVManager) observeBackend(caller context.Context, cfg config.AVConfig, epoch uint64, capability, canary bool) (bool, string, string) {
	if !cfg.Enabled {
		return false, "", "disabled"
	}
	m.mu.Lock()
	seq := m.nextProbeLocked()
	states := make(map[avscan.Direction]avDirectionHealth, len(m.directions))
	for dir, state := range m.directions {
		states[dir] = state
	}
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(caller, min(avTimeout(cfg), avStatusProbeTimeout))
	defer cancel()
	stop := context.AfterFunc(m.ctx, cancel)
	defer stop()
	var version string
	var probeErr error
	ttl := avObserveInterval
	if capability {
		switch avMode(cfg) {
		case "icap":
			var options icapOptions
			options, probeErr = m.icapClient(cfg).options(ctx, firstICAPServer(cfg))
			if probeErr == nil {
				ttl = options.ttl
			}
			for dir, state := range states {
				method := icapRESPMOD
				if dir == avscan.Upload {
					method = icapREQMOD
				}
				state.capable = probeErr == nil && listsMethod(options.methods, method)
				state.capabilityError = ""
				if !state.capable {
					state.capabilityError = fmt.Sprintf("icap service does not support %s (methods %q)", method, options.methods)
				}
				states[dir] = state
			}
		case "clamav":
			client := &ClamAVClient{Timeout: avStatusProbeTimeout, Socket: clamdSocket(cfg)}
			probeErr = client.Ping(ctx)
			if probeErr == nil {
				version, probeErr = client.Version(ctx)
			}
			for dir, state := range states {
				state.capable = probeErr == nil
				states[dir] = state
			}
		default:
			probeErr = fmt.Errorf("unsupported mode %q", avMode(cfg))
		}
	}
	scanned := make(map[avscan.Direction]bool)
	if canary && probeErr == nil {
		for _, dir := range scanDirections(cfg) {
			state := states[dir]
			if state.healthy || !state.capable {
				continue
			}
			err := m.scanCanary(ctx, cfg, dir)
			state.healthy, state.scanError = err == nil, ""
			if err != nil {
				state.scanError = fmt.Sprintf("%s scan canary: %v", dir, err)
			}
			states[dir] = state
			scanned[dir] = true
			if err != nil && !errors.Is(err, errScanProtocol) {
				// A canary transport error has the same meaning as a user scan's.
				probeErr = err
				capability = true
				ttl = avObserveInterval
				for d, s := range states {
					s.capable = false
					states[d] = s
				}
				break
			}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	diagnostic := ""
	if err := callerEnded(caller); err != nil {
		diagnostic = err.Error()
	} else if m.currentProbeLocked(epoch) {
		wasReady, next := m.backendReady, m.nextOptions
		publishCapability := capability && seq >= m.capabilitySeq
		if publishCapability {
			m.capabilitySeq = seq
			m.capabilityError = ""
			if probeErr != nil {
				m.capabilityError = probeErr.Error()
			}
			m.nextOptions = time.Now().Add(ttl)
		}
		for dir, observed := range states {
			state, ok := m.directions[dir]
			if !ok {
				continue
			}
			if publishCapability {
				state.capable, state.capabilityError = observed.capable, observed.capabilityError
			}
			if scanned[dir] && seq >= state.scanSeq {
				state.scanSeq = seq
				state.healthy, state.scanError = observed.healthy, observed.scanError
			}
			m.directions[dir] = state
		}
		m.lastTest = time.Now().UTC()
		m.refreshBackendLocked()
		if wasReady && !m.backendReady || m.backendReady && m.nextOptions.Before(next) {
			m.wakeObserverLocked()
		}
	}
	if diagnostic != "" {
		return false, version, diagnostic
	}
	return m.backendReady, version, m.backendError
}

// startObserver and stopObserver require op. Failed applies are retried, but
// no autonomous ICAP traffic is sent while no direction is selected. Successful
// OPTIONS is cached for its TTL (capped at 30s); unhealthy paths retry canaries
// every second without forcing an OPTIONS refresh before that TTL expires.
func (m *AVManager) startObserver(cfg config.AVConfig, epoch uint64) {
	if !cfg.Enabled || (avMode(cfg) == "icap" && len(scanDirections(cfg)) == 0) || (avMode(cfg) != "icap" && avMode(cfg) != "clamav") {
		return
	}
	ctx, cancel := context.WithCancel(m.ctx)
	done := make(chan struct{})
	m.observeCancel, m.observeDone = cancel, done
	wake := make(chan struct{}, 1)
	m.mu.Lock()
	m.observeWake = wake
	m.mu.Unlock()
	go func() {
		defer close(done)
		timer := time.NewTimer(m.observerDelay())
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-wake:
				timer.Reset(m.observerDelay())
			case <-timer.C:
				m.mu.Lock()
				due := !time.Now().Before(m.nextOptions)
				m.mu.Unlock()
				m.observeBackend(ctx, cfg, epoch, due, true)
				timer.Reset(m.observerDelay())
			}
		}
	}()
}

func (m *AVManager) observerDelay() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	delay := max(time.Until(m.nextOptions), avObserveInterval)
	if !m.backendReady {
		delay = avObserveInterval
	}
	return delay
}

func (m *AVManager) stopObserver() {
	if m.observeCancel != nil {
		m.observeCancel()
		<-m.observeDone
		m.observeCancel, m.observeDone = nil, nil
		m.mu.Lock()
		m.observeWake = nil
		m.mu.Unlock()
	}
}

// callerEnded reports the caller's end. A probe bounded by the caller's
// deadline can fail with an I/O timeout before the context timer marks the
// context done; that failure is the caller's, not the backend's.
func callerEnded(caller context.Context) error {
	if err := caller.Err(); err != nil {
		return err
	}
	if d, ok := caller.Deadline(); ok && !time.Now().Before(d) {
		return context.DeadlineExceeded
	}
	return nil
}
