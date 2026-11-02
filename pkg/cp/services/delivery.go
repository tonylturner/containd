// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// DeliveryResult separates the safe compilation projection from delivery proof.
// DHCP here is render-only; only dhcpd.Manager can acknowledge its runtime.
// AV remains owned by AVManager; WireGuard remains owned by the engine.
// Requirements are deliberately absent: protection.Requirements is authoritative.
type DeliveryResult struct {
	Effective config.ServicesConfig
	Outcomes  []protection.OwnerOutcome
}

type deliveryState struct {
	meta     protection.Metadata
	desired  config.ServicesConfig
	initial  []config.ServiceConfigError
	outcomes []protection.OwnerOutcome
}

var ErrDeliverySuperseded = errors.New("service delivery target is not current")

func deliveryOutcome(meta protection.Metadata, name protection.SubsystemName, owner protection.Owner, enabled bool, attempt int, err error) protection.OwnerOutcome {
	op := protection.OperationApply
	if !enabled {
		op = protection.OperationStop
	}
	out := protection.OwnerOutcome{Name: name, Owner: owner, DesiredRevision: meta.RunningRevision, Operation: op, State: protection.DeliveryPending, Attempt: attempt, ObservedAt: time.Now().UTC()}
	if err != nil {
		kind := protection.FaultDelivery
		var typed *config.ServiceConfigError
		var render *daemonRenderError
		var publication *daemonPublicationError
		var delivery *daemonDeliveryError
		switch {
		case errors.As(err, &delivery), errors.As(err, &publication), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		case errors.As(err, &render):
			kind = protection.FaultRender
		case errors.As(err, &typed), errors.Is(err, ErrAVInvalid):
			kind = protection.FaultConfig
		}
		out.State = protection.DeliveryFailed
		out.Retryable = kind == protection.FaultDelivery
		out.Reason = "service delivery failed"
		if kind == protection.FaultConfig {
			out.Reason = "service configuration rejected"
		}
		if kind == protection.FaultRender {
			out.Reason = "service render rejected"
		}
		out.Fault = &protection.Fault{Kind: kind, Reason: out.Reason}
		return out
	}
	out.State = protection.DeliveryReady
	if !enabled {
		out.State = protection.DeliveryOff
	}
	out.Reason = "owner completed requested operation"
	out.Acknowledged = &protection.Acknowledgement{Metadata: meta, Operation: op}
	return out
}

func cloneServices(cfg config.ServicesConfig) config.ServicesConfig {
	// ServicesConfig contains only JSON configuration values. Never retain caller
	// slices, credential pointers or mutable candidate storage across retries.
	b, _ := json.Marshal(cfg)
	var detached config.ServicesConfig
	_ = json.Unmarshal(b, &detached)
	return detached
}

func cloneOutcomes(in []protection.OwnerOutcome) []protection.OwnerOutcome {
	out := append([]protection.OwnerOutcome{}, in...)
	for i := range out {
		if out[i].Acknowledged != nil {
			v := *out[i].Acknowledged
			out[i].Acknowledged = &v
		}
		if out[i].Fault != nil {
			v := *out[i].Fault
			out[i].Fault = &v
		}
	}
	return out
}

// ApplyDelivery invalidates every prior proof before applying a detached desired
// snapshot. initial must describe the original desired input, not its quarantine.
func (m *Manager) ApplyDelivery(ctx context.Context, meta protection.Metadata, desired config.ServicesConfig, initial []config.ServiceConfigError) (DeliveryResult, error) {
	if !meta.Valid() {
		return DeliveryResult{}, errors.New("invalid service delivery identity")
	}
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	m.delivery = deliveryState{meta: meta, desired: cloneServices(desired), initial: append([]config.ServiceConfigError(nil), initial...)}
	return m.deliverLocked(ctx, false), nil
}

// RetryDelivery retries only retryable failed owners, preserving healthy owners
// and terminal input faults. It never replays the entire service configuration.
func (m *Manager) RetryDelivery(ctx context.Context, meta protection.Metadata) (DeliveryResult, error) {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	if !meta.Valid() || m.delivery.meta != meta {
		return DeliveryResult{}, ErrDeliverySuperseded
	}
	m.refreshDeliveryLocked()
	return m.deliverLocked(ctx, true), nil
}

// StopDelivery requests independently verified owner teardown, not shutdown of
// the manager. It remains retryable with the same identity after a failed stop.
func (m *Manager) StopDelivery(ctx context.Context, meta protection.Metadata) (DeliveryResult, error) {
	return m.ApplyDelivery(ctx, meta, config.ServicesConfig{}, nil)
}

// DeliveryOutcomes returns detached proof without making unrelated live probes.
func (m *Manager) DeliveryOutcomes() []protection.OwnerOutcome {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	m.refreshDeliveryLocked()
	return cloneOutcomes(m.delivery.outcomes)
}

func (m *Manager) deliverLocked(ctx context.Context, retry bool) DeliveryResult {
	s := &m.delivery
	effective := cloneServices(s.desired)
	faults := ConfigFaults(s.initial)
	for _, fault := range s.initial {
		config.QuarantineService(&effective, fault.Service)
	}
	old := s.outcomes
	s.outcomes = nil // invalidate before ANY owner mutation
	run := func(name protection.SubsystemName, service string, enabled bool, fn func() error, stop func() error) {
		var previous *protection.OwnerOutcome
		for i := range old {
			if old[i].Name == name {
				previous = &old[i]
				break
			}
		}
		var out protection.OwnerOutcome
		if retry && previous != nil && !previous.Retryable {
			out = *previous
		} else {
			attempt := 1
			if previous != nil {
				attempt = previous.Attempt + 1
			}
			var err error
			for _, f := range s.initial {
				if f.Service == service {
					err = &config.ServiceConfigError{Service: service, Err: errors.New("invalid desired service")}
					break
				}
			}
			if err == nil {
				err = ctx.Err()
			}
			if err == nil {
				err = fn()
			}
			out = deliveryOutcome(s.meta, name, protection.OwnerManagement, enabled, attempt, err)
			if err != nil && enabled && stop != nil {
				// A successful quarantine stop is NOT proof of the desired enabled input.
				// A failed stop likewise must never acquire a disabled acknowledgement.
				if stopErr := stop(); stopErr != nil {
					out.Reason += "; quarantine stop not confirmed"
				}
			}
		}
		if out.Fault != nil {
			quarantineOutcome(&effective, name, service)
			kind := "runtime"
			if out.Fault.Kind != protection.FaultDelivery {
				kind = "config"
			}
			found := false
			for _, f := range faults {
				found = found || f.Service == service
			}
			if !found {
				faults = append(faults, ServiceFault{Service: service, Kind: kind, Message: out.Fault.Reason})
			}
		}
		s.outcomes = append(s.outcomes, out)
	}
	if m.Syslog != nil {
		run(protection.SubsystemSyslog, config.ServiceSyslog, len(s.desired.Syslog.Forwarders) > 0, func() error { return m.Syslog.Apply(ctx, s.desired.Syslog) }, func() error { return m.Syslog.Apply(ctx, config.SyslogConfig{}) })
	}
	if m.DNS != nil {
		run(protection.SubsystemDNS, config.ServiceDNS, s.desired.DNS.Enabled, func() error { return m.DNS.Apply(ctx, s.desired.DNS) }, func() error { return m.DNS.Apply(ctx, config.DNSConfig{}) })
	}
	if m.NTP != nil {
		run(protection.SubsystemNTP, config.ServiceNTP, s.desired.NTP.Enabled, func() error {
			err := m.NTP.Apply(ctx, s.desired.NTP)
			if err == nil && s.desired.NTP.Enabled && m.NTP.Supervise && m.NTP.Status()["running"] != true {
				return errors.New("NTP not running")
			}
			return err
		}, func() error { return m.NTP.Apply(ctx, config.NTPConfig{}) })
	}
	if m.Proxy != nil {
		run(protection.SubsystemForwardProxy, config.ServiceProxy, s.desired.Proxy.Forward.Enabled, func() error { return m.Proxy.applySide(ctx, s.desired.Proxy, true) }, func() error { return m.Proxy.applySide(ctx, config.ProxyConfig{}, true) })
		run(protection.SubsystemReverseProxy, config.ServiceProxy, s.desired.Proxy.Reverse.Enabled, func() error { return m.Proxy.applySide(ctx, s.desired.Proxy, false) }, func() error { return m.Proxy.applySide(ctx, config.ProxyConfig{}, false) })
	}
	if m.VPN != nil {
		run(protection.SubsystemOpenVPN, config.ServiceOpenVPN, s.desired.VPN.OpenVPN.Enabled, func() error { return m.VPN.applyDelivery(ctx, s.desired.VPN) }, func() error { return m.VPN.applyDelivery(ctx, config.VPNConfig{}) })
	}
	// Management renders DHCP only. Never fabricate an engine runtime ack from
	// writing dhcp.json, including when the requested service is disabled.
	if m.DHCP != nil {
		run(protection.SubsystemDHCP, config.ServiceDHCP, s.desired.DHCP.Enabled, func() error { return m.DHCP.Apply(ctx, s.desired.DHCP) }, nil)
		out := &s.outcomes[len(s.outcomes)-1]
		out.Owner = protection.OwnerEngine
		if out.Fault == nil {
			out.State = protection.DeliveryPending
			out.Acknowledged = nil
			out.Reason = "awaiting engine DHCP runtime outcome"
		}
	}
	m.localFaults = faults
	m.publishCombinedFaults()
	return DeliveryResult{Effective: effective, Outcomes: cloneOutcomes(s.outcomes)}
}

func quarantineOutcome(cfg *config.ServicesConfig, name protection.SubsystemName, service string) {
	switch name {
	case protection.SubsystemForwardProxy:
		cfg.Proxy.Forward.Enabled = false
	case protection.SubsystemReverseProxy:
		cfg.Proxy.Reverse.Enabled = false
	default:
		config.QuarantineService(cfg, service)
	}
}

// Runtime handles are existing owner observations, not new network probes. A
// dead traffic daemon revokes its proof before a coordinator chooses retries.
func (m *Manager) refreshDeliveryLocked() {
	for i := range m.delivery.outcomes {
		out := &m.delivery.outcomes[i]
		if out.Acknowledged == nil || out.Operation != protection.OperationApply {
			continue
		}
		live := true
		switch out.Name {
		case protection.SubsystemOpenVPN:
			m.VPN.mu.Lock()
			live = m.VPN.ovpnRunning && m.VPN.ovpnCmd != nil
			if live {
				select {
				case <-m.VPN.ovpnWaitCh:
					live = false
				default:
				}
			}
			m.VPN.mu.Unlock()
		case protection.SubsystemForwardProxy, protection.SubsystemReverseProxy:
			m.Proxy.mu.Lock()
			cmd, done := m.Proxy.envoyCmd, m.Proxy.envoyDone
			if out.Name == protection.SubsystemReverseProxy {
				cmd, done = m.Proxy.nginxCmd, m.Proxy.nginxDone
			}
			live = cmd != nil && done != nil
			if live {
				select {
				case <-done:
					live = false
				default:
				}
			}
			m.Proxy.mu.Unlock()
		}
		if !live {
			*out = deliveryOutcome(m.delivery.meta, out.Name, out.Owner, true, out.Attempt, errors.New("traffic daemon exited"))
		}
	}
}

// daemonDeliveryError preserves transient classification through config wrappers.
type daemonDeliveryError struct{ error }

func (e *daemonDeliveryError) Unwrap() error { return e.error }
