// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"errors"
	"reflect"
	"sync"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
)

type avDelivery struct {
	applied bool
	trust   string
	mu      sync.Mutex
	meta    protection.Metadata
	cfg     config.AVConfig
	outcome protection.OwnerOutcome
}

// ApplyDelivery labels the existing AV owner; it does not create a supervisor.
// Unchanged confirmed inputs are adopted only after checking owner readiness.
func (m *AVManager) ApplyDelivery(ctx context.Context, meta protection.Metadata, cfg config.AVConfig) (protection.OwnerOutcome, error) {
	if !meta.Valid() {
		return protection.OwnerOutcome{}, errors.New("invalid AV delivery identity")
	}
	cfg = cloneServices(config.ServicesConfig{AV: cfg}).AV
	m.delivery.mu.Lock()
	defer m.delivery.mu.Unlock()
	m.observeDeliveryLocked()
	d := &m.delivery
	trust := m.deliveryTrust(cfg)
	if d.meta == meta && d.trust != trust {
		return protection.OwnerOutcome{}, ErrDeliverySuperseded
	}
	if reflect.DeepEqual(d.cfg, cfg) && d.meta.Valid() && d.trust == trust {
		if d.outcome.Acknowledged != nil && m.deliveryRuntimeMatchesLocked() {
			if d.meta != meta {
				d.outcome = deliveryOutcome(meta, protection.SubsystemAV, protection.OwnerManagement, cfg.Enabled, d.outcome.Attempt, nil)
			}
			d.meta = meta
			return cloneOutcomes([]protection.OwnerOutcome{d.outcome})[0], nil
		}
		if d.outcome.Fault != nil && !d.outcome.Retryable && d.meta == meta {
			d.meta = meta
			d.outcome.DesiredRevision = meta.RunningRevision
			return cloneOutcomes([]protection.OwnerOutcome{d.outcome})[0], nil
		}
	}
	attempt := d.outcome.Attempt + 1
	m.delivery.meta = meta
	m.delivery.trust = trust
	m.delivery.cfg = cfg
	m.delivery.outcome = protection.OwnerOutcome{} // invalidate before mutation
	applied, err := m.applyDeliveryInput(ctx, m.delivery.cfg)
	m.delivery.applied = applied
	m.delivery.outcome = avDeliveryOutcome(meta, cfg.Enabled, attempt, err)
	return cloneOutcomes([]protection.OwnerOutcome{m.delivery.outcome})[0], nil
}

// RetryDelivery first observes the existing supervisor's readiness. It only
// reapplies this owner if delivery is still failed, never other services.
func (m *AVManager) RetryDelivery(ctx context.Context, meta protection.Metadata) (protection.OwnerOutcome, error) {
	m.delivery.mu.Lock()
	defer m.delivery.mu.Unlock()
	if !meta.Valid() || m.delivery.meta != meta || m.delivery.trust != m.deliveryTrust(m.delivery.cfg) {
		return protection.OwnerOutcome{}, ErrDeliverySuperseded
	}
	m.observeDeliveryLocked()
	if m.delivery.outcome.Retryable {
		attempt := m.delivery.outcome.Attempt + 1
		m.delivery.outcome = protection.OwnerOutcome{}
		applied, err := m.applyDeliveryInput(ctx, m.delivery.cfg)
		m.delivery.applied = applied
		m.delivery.outcome = avDeliveryOutcome(meta, m.delivery.cfg.Enabled, attempt, err)
	}
	return cloneOutcomes([]protection.OwnerOutcome{m.delivery.outcome})[0], nil
}

func (m *AVManager) StopDelivery(ctx context.Context, meta protection.Metadata) (protection.OwnerOutcome, error) {
	return m.ApplyDelivery(ctx, meta, config.AVConfig{})
}

// DeliveryOutcome revokes earlier success on current scanner loss, and adopts
// positive recovery from AV's own observer without restarting a healthy backend.
func (m *AVManager) DeliveryOutcome() protection.OwnerOutcome {
	m.delivery.mu.Lock()
	defer m.delivery.mu.Unlock()
	m.observeDeliveryLocked()
	return cloneOutcomes([]protection.OwnerOutcome{m.delivery.outcome})[0]
}

func (m *AVManager) observeDeliveryLocked() {
	d := &m.delivery
	if d.meta.Valid() && d.trust != m.deliveryTrust(d.cfg) {
		d.outcome.Acknowledged = nil
		d.outcome.State, d.outcome.Retryable = protection.DeliveryPending, false
		d.outcome.Reason = "trust changed; fresh delivery attempt required"
		return
	}
	if !d.applied || !d.meta.Valid() || !d.cfg.Enabled || d.outcome.Fault != nil && !d.outcome.Retryable {
		return
	}
	ready := m.deliveryRuntimeMatchesLocked()
	var err error
	if !ready {
		err = errors.New("AV backend not ready")
	}
	d.outcome = deliveryOutcome(d.meta, protection.SubsystemAV, protection.OwnerManagement, true, d.outcome.Attempt, err)
}

func (m *AVManager) deliveryRuntimeMatchesLocked() bool {
	m.mu.Lock()
	same := reflect.DeepEqual(m.lastCfg, m.delivery.cfg)
	stopped := m.clamd.cmd == nil && m.fresh.done == nil
	m.mu.Unlock()
	if !same || m.ctx.Err() != nil {
		return false
	}
	if !m.delivery.cfg.Enabled {
		return stopped
	}
	ready, _ := m.Ready()
	return ready
}

func avDeliveryOutcome(meta protection.Metadata, enabled bool, attempt int, err error) protection.OwnerOutcome {
	out := deliveryOutcome(meta, protection.SubsystemAV, protection.OwnerManagement, enabled, attempt, err)
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		out.State, out.Fault, out.Retryable = protection.DeliveryPending, nil, true
		out.Reason = "AV backend is still starting"
	}
	return out
}

// Only a configuration actually handed to the owner's lifetime observer can
// later recover from a request timeout. Cancellation before the operation lock
// must never certify a different, still-running configuration.
func (m *AVManager) applyDeliveryInput(ctx context.Context, cfg config.AVConfig) (bool, error) {
	m.mu.Lock()
	before := m.lastRender
	m.mu.Unlock()
	err := m.apply(ctx, cfg)
	m.mu.Lock()
	rendered := m.lastRender != before && reflect.DeepEqual(m.lastCfg, cfg)
	m.mu.Unlock()
	pending := errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
	return err == nil || pending && rendered, err
}

func avUsesTrust(cfg config.AVConfig) bool {
	if !cfg.Enabled {
		return false
	}
	if avMode(cfg) == "clamav" {
		return cfg.ClamAV.FreshclamEnabled
	}
	for _, server := range cfg.ICAP.Servers {
		if server.UseTLS {
			return true
		}
	}
	return false
}

func (m *AVManager) deliveryTrust(cfg config.AVConfig) string {
	if avUsesTrust(cfg) {
		return m.TrustRevision()
	}
	return ""
}
