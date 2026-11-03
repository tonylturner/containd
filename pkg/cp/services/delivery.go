// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
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
	inputs   map[protection.SubsystemName]any
	runtime  map[protection.SubsystemName]string
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

// ApplyDelivery positively adopts unchanged live owners and delivers outstanding
// owners from a detached snapshot. initial describes desired input, not quarantine.
func (m *Manager) ApplyDelivery(ctx context.Context, meta protection.Metadata, desired config.ServicesConfig, initial []config.ServiceConfigError) (DeliveryResult, error) {
	if !meta.Valid() {
		return DeliveryResult{}, errors.New("invalid service delivery identity")
	}
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	fresh := m.delivery.meta != meta
	m.refreshDeliveryLocked()
	m.delivery.meta = meta
	m.delivery.desired = cloneServices(desired)
	m.delivery.initial = append([]config.ServiceConfigError(nil), initial...)
	if m.delivery.inputs == nil {
		m.delivery.inputs = map[protection.SubsystemName]any{}
		m.delivery.runtime = map[protection.SubsystemName]string{}
	}
	return m.deliverLocked(ctx, false, fresh), nil
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
	return m.deliverLocked(ctx, true, false), nil
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

func (m *Manager) deliverLocked(ctx context.Context, retry, fresh bool) DeliveryResult {
	s := &m.delivery
	effective := cloneServices(s.desired)
	faults := ConfigFaults(s.initial)
	for _, fault := range s.initial {
		config.QuarantineService(&effective, fault.Service)
	}

	run := func(name protection.SubsystemName, service string, enabled bool, fn func() error, stop func() error) {
		m.deliverOwnerLocked(ctx, name, service, enabled, retry, fresh, fn, stop, &effective, &faults)
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

// Caller holds applyMu. Only this owner's proof is revoked before its callback.
func (m *Manager) deliverOwnerLocked(ctx context.Context, name protection.SubsystemName, service string, enabled, retry, fresh bool, fn func() error, stop func() error, effective *config.ServicesConfig, faults *[]ServiceFault) {
	s := &m.delivery

	var previous *protection.OwnerOutcome
	for i := range s.outcomes {
		if s.outcomes[i].Name == name {
			prior := s.outcomes[i]
			previous = &prior
			break
		}
	}
	invalid := false
	for _, f := range s.initial {
		invalid = invalid || f.Service == service
	}
	input := struct {
		Config  any
		Invalid bool
	}{serviceOwnerInput(s.desired, name), invalid}
	same := reflect.DeepEqual(s.inputs[name], input)
	var out protection.OwnerOutcome
	if previous != nil && same && !invalid && previous.Acknowledged != nil {
		out = *previous
		if previous.Acknowledged.Metadata != s.meta {
			if runtime, live := m.ownerRuntime(name, enabled); live && runtime == s.runtime[name] {
				out = deliveryOutcome(s.meta, name, previous.Owner, enabled, previous.Attempt, nil)
			} else {
				previous.Acknowledged = nil
				previous.Retryable = true
			}
		}
	}
	if previous != nil && same && !invalid && previous.Acknowledged != nil {
		// Adopted above, or retained on the same attempt.
	} else if !fresh && (retry || same) && previous != nil && !previous.Retryable && previous.Acknowledged == nil {
		out = *previous
		out.DesiredRevision = s.meta.RunningRevision
	} else {
		attempt := 1
		if previous != nil {
			attempt = previous.Attempt + 1
		}
		for i := range s.outcomes {
			if s.outcomes[i].Name == name {
				s.outcomes[i].Acknowledged = nil
				s.outcomes[i].State = protection.DeliveryPending
			}
		}
		s.inputs[name] = input
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
		if err == nil {
			s.runtime[name], _ = m.ownerRuntime(name, enabled)
		}
		if err != nil && enabled && stop != nil {
			// A successful quarantine stop is NOT proof of the desired enabled input.
			// A failed stop likewise must never acquire a disabled acknowledgement.
			if stopErr := stop(); stopErr != nil {
				out.Reason += "; quarantine stop not confirmed"
			}
		}
	}
	if out.Fault != nil {
		quarantineOutcome(effective, name, service)
		kind := "runtime"
		if out.Fault.Kind != protection.FaultDelivery {
			kind = "config"
		}
		found := false
		for _, f := range *faults {
			found = found || f.Service == service
		}
		if !found {
			*faults = append(*faults, ServiceFault{Service: service, Kind: kind, Message: out.Fault.Reason})
		}
	}
	replaced := false
	for i := range s.outcomes {
		if s.outcomes[i].Name == name {
			s.outcomes[i] = out
			replaced = true
			break
		}
	}
	if !replaced {
		s.outcomes = append(s.outcomes, out)
	}
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

// Existing owner observations revoke success before retry/adoption decisions.
func (m *Manager) refreshDeliveryLocked() {
	for i := range m.delivery.outcomes {
		out := &m.delivery.outcomes[i]
		if out.Acknowledged == nil {
			continue
		}
		runtime, live := m.ownerRuntime(out.Name, out.Operation == protection.OperationApply)
		if !live || runtime != m.delivery.runtime[out.Name] {
			*out = deliveryOutcome(m.delivery.meta, out.Name, out.Owner, out.Operation == protection.OperationApply, out.Attempt, errors.New("owner runtime no longer matches"))
		}
	}
}

// daemonDeliveryError preserves transient classification through config wrappers.
type daemonDeliveryError struct{ error }

func (e *daemonDeliveryError) Unwrap() error { return e.error }
