// SPDX-License-Identifier: Apache-2.0
package dhcpd

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
)

type delivery struct {
	applied bool
	mu      sync.Mutex
	meta    protection.Metadata
	cfg     config.DHCPConfig
	ifaces  []config.Interface
	outcome protection.OwnerOutcome
}

var ErrDeliverySuperseded = errors.New("DHCP delivery target is not current")

// ApplyDelivery labels the existing DHCP owner, including actual listener
// readiness and joined teardown. It never starts a second retry supervisor.
func (m *Manager) ApplyDelivery(ctx context.Context, meta protection.Metadata, cfg config.DHCPConfig, ifaces []config.Interface) (protection.OwnerOutcome, error) {
	if !meta.Valid() {
		return protection.OwnerOutcome{}, errors.New("invalid DHCP delivery identity")
	}
	m.delivery.mu.Lock()
	defer m.delivery.mu.Unlock()
	d := &m.delivery
	d.meta = meta
	d.cfg = config.DHCPConfig{}
	d.ifaces = nil
	data, _ := json.Marshal(cfg)
	_ = json.Unmarshal(data, &d.cfg)
	data, _ = json.Marshal(ifaces)
	_ = json.Unmarshal(data, &d.ifaces)
	d.outcome = protection.OwnerOutcome{}
	err := m.apply(ctx, d.cfg, d.ifaces)
	d.applied = err == nil
	d.outcome = m.makeOutcome(meta, cfg.Enabled, 1, err)
	return detached(d.outcome), nil
}

func (m *Manager) RetryDelivery(ctx context.Context, meta protection.Metadata) (protection.OwnerOutcome, error) {
	m.delivery.mu.Lock()
	defer m.delivery.mu.Unlock()
	d := &m.delivery
	if !meta.Valid() || d.meta != meta {
		return protection.OwnerOutcome{}, ErrDeliverySuperseded
	}
	m.observeDeliveryLocked()
	if d.outcome.Retryable {
		attempt := d.outcome.Attempt + 1
		d.outcome = protection.OwnerOutcome{}
		err := m.apply(ctx, d.cfg, d.ifaces)
		d.applied = err == nil
		d.outcome = m.makeOutcome(meta, d.cfg.Enabled, attempt, err)
	}
	return detached(d.outcome), nil
}

func (m *Manager) StopDelivery(ctx context.Context, meta protection.Metadata) (protection.OwnerOutcome, error) {
	return m.ApplyDelivery(ctx, meta, config.DHCPConfig{}, nil)
}

func (m *Manager) DeliveryOutcome() protection.OwnerOutcome {
	m.delivery.mu.Lock()
	defer m.delivery.mu.Unlock()
	m.observeDeliveryLocked()
	return detached(m.delivery.outcome)
}

func (m *Manager) observeDeliveryLocked() {
	d := &m.delivery
	if !d.applied || !d.meta.Valid() || !d.cfg.Enabled || d.outcome.Fault != nil && !d.outcome.Retryable {
		return
	}
	d.outcome = m.makeOutcome(d.meta, true, d.outcome.Attempt, nil)
}

func (m *Manager) makeOutcome(meta protection.Metadata, enabled bool, attempt int, err error) protection.OwnerOutcome {
	op := protection.OperationApply
	if !enabled {
		op = protection.OperationStop
	}
	out := protection.OwnerOutcome{Name: protection.SubsystemDHCP, Owner: protection.OwnerEngine, DesiredRevision: meta.RunningRevision, Operation: op, State: protection.DeliveryReady, Attempt: attempt, ObservedAt: time.Now().UTC(), Reason: "DHCP owner completed operation"}
	var typed *config.ServiceConfigError
	kind := protection.FaultDelivery
	if errors.As(err, &typed) {
		kind = protection.FaultConfig
	}
	if err != nil {
		out.State = protection.DeliveryFailed
		out.Reason = "DHCP delivery failed"
		out.Retryable = kind == protection.FaultDelivery
		out.Fault = &protection.Fault{Kind: kind, Reason: out.Reason}
		return out
	}
	if enabled && !m.runtimeReady() {
		out.State = protection.DeliveryPending
		out.Reason = "DHCP listeners not ready"
		out.Retryable = true
		return out
	}
	if !enabled {
		out.State = protection.DeliveryOff
	}
	out.Acknowledged = &protection.Acknowledgement{Metadata: meta, Operation: op}
	return out
}

func detached(out protection.OwnerOutcome) protection.OwnerOutcome {
	if out.Acknowledged != nil {
		v := *out.Acknowledged
		out.Acknowledged = &v
	}
	if out.Fault != nil {
		v := *out.Fault
		out.Fault = &v
	}
	return out
}

// Apply is the existing unlabelled engine entry point. Any direct mutation
// revokes the labelled proof; consumers must not keep an old attempt's ack.
func (m *Manager) Apply(ctx context.Context, cfg config.DHCPConfig, ifaces []config.Interface) error {
	m.delivery.mu.Lock()
	defer m.delivery.mu.Unlock()
	m.delivery.meta = protection.Metadata{}
	m.delivery.outcome = protection.OwnerOutcome{}
	return m.apply(ctx, cfg, ifaces)
}
