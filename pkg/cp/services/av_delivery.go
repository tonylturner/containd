// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"errors"
	"sync"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
)

type avDelivery struct {
	applied bool
	mu      sync.Mutex
	meta    protection.Metadata
	cfg     config.AVConfig
	outcome protection.OwnerOutcome
}

// ApplyDelivery labels the existing AV owner; it does not create a supervisor.
// Existing Apply and Ready remain the engine's entry points.
func (m *AVManager) ApplyDelivery(ctx context.Context, meta protection.Metadata, cfg config.AVConfig) (protection.OwnerOutcome, error) {
	if !meta.Valid() {
		return protection.OwnerOutcome{}, errors.New("invalid AV delivery identity")
	}
	m.delivery.mu.Lock()
	defer m.delivery.mu.Unlock()
	m.delivery.meta = meta
	m.delivery.cfg = cloneServices(config.ServicesConfig{AV: cfg}).AV
	m.delivery.outcome = protection.OwnerOutcome{} // invalidate before mutation
	err := m.apply(ctx, m.delivery.cfg)
	m.delivery.applied = err == nil
	m.delivery.outcome = deliveryOutcome(meta, protection.SubsystemAV, protection.OwnerManagement, cfg.Enabled, 1, err)
	return cloneOutcomes([]protection.OwnerOutcome{m.delivery.outcome})[0], nil
}

// RetryDelivery first observes the existing supervisor's readiness. It only
// reapplies this owner if delivery is still failed, never other services.
func (m *AVManager) RetryDelivery(ctx context.Context, meta protection.Metadata) (protection.OwnerOutcome, error) {
	m.delivery.mu.Lock()
	defer m.delivery.mu.Unlock()
	if !meta.Valid() || m.delivery.meta != meta {
		return protection.OwnerOutcome{}, ErrDeliverySuperseded
	}
	m.observeDeliveryLocked()
	if m.delivery.outcome.Retryable {
		attempt := m.delivery.outcome.Attempt + 1
		m.delivery.outcome = protection.OwnerOutcome{}
		err := m.apply(ctx, m.delivery.cfg)
		m.delivery.applied = err == nil
		m.delivery.outcome = deliveryOutcome(meta, protection.SubsystemAV, protection.OwnerManagement, m.delivery.cfg.Enabled, attempt, err)
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
	if !d.applied || !d.meta.Valid() || !d.cfg.Enabled || d.outcome.Fault != nil && !d.outcome.Retryable {
		return
	}
	ready, _ := m.Ready()
	var err error
	if !ready {
		err = errors.New("AV backend not ready")
	}
	d.outcome = deliveryOutcome(d.meta, protection.SubsystemAV, protection.OwnerManagement, true, d.outcome.Attempt, err)
}
