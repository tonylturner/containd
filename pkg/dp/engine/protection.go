// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"crypto/rand"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/events"
)

// ProtectionStatus is an engine-owned observation, not an apply acknowledgement.
// It is shared with the engine API client; slices returned by Protection are copies.
type ProtectionStatus struct {
	RunningRevision  protection.Revision         `json:"runningRevision"`
	Mode             protection.ApplyMode        `json:"mode"`
	Installed        *protection.Acknowledgement `json:"installed"`
	Subsystems       []protection.OwnerOutcome   `json:"subsystems"`
	BootID           string                      `json:"bootId"`
	ApplyID          string                      `json:"applyId"`
	InstalledApplyID string                      `json:"installedApplyId"`
	State            string                      `json:"state"`
	Retryable        bool                        `json:"retryable"`
	ObservedAt       time.Time                   `json:"observedAt"`
	Components       []ProtectionComponent       `json:"components"`
	Effects          []ProtectionEffect          `json:"effects"`
}

type ProtectionComponent struct {
	Name        string    `json:"name"`
	Required    bool      `json:"required"`
	State       string    `json:"state"`
	Reason      string    `json:"reason"`
	Attempt     int       `json:"attempt,omitempty"`
	MaxAttempts int       `json:"maxAttempts,omitempty"`
	Since       time.Time `json:"since"`
}

type ProtectionEffect struct {
	Traffic string `json:"traffic"`
	Effect  string `json:"effect"`
}

// protectionState has no dependency on lifecycle, policy, gate or capture locks.
// Callbacks carry the capture epoch and cannot modify a replacement run.
type protectionState struct {
	mu               sync.Mutex
	status           ProtectionStatus
	components       map[string]ProtectionComponent
	epoch            uint64
	enabled          bool
	configured       bool
	envelope, direct bool
	queue            string
	policyFault      bool
	iecFault         string
	steeringFault    bool
	gateUnknown      bool
	ruleReconciling  bool
	applying         bool
	installFailed    bool
	nflogLost        bool
	ruleInputApply   string
	ruleInput        []byte
	installedInput   []byte
	outcomes         map[protection.SubsystemName]protection.OwnerOutcome
	serviceOutcomes  func() []protection.OwnerOutcome
	store            *events.Writer
}

func newProtection(store *events.Writer) *protectionState {
	p := &protectionState{store: store, components: map[string]ProtectionComponent{}, outcomes: map[protection.SubsystemName]protection.OwnerOutcome{}}
	p.status = ProtectionStatus{BootID: rand.Text(), State: "pending", Components: []ProtectionComponent{}, Effects: []ProtectionEffect{}}
	p.setLocked("nft", "pending", "awaiting configuration", 0, 0)
	return p
}

func (p *protectionState) setLocked(name, state, reason string, attempt, max int) {
	old := p.components[name]
	since := old.Since
	if old.State != state || old.Reason != reason || since.IsZero() {
		since = time.Now().UTC()
	}
	p.components[name] = ProtectionComponent{Name: name, Required: old.Required, State: state, Reason: reason, Attempt: attempt, MaxAttempts: max, Since: since}
}

func (p *protectionState) update(fn func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fn()
	p.recomputeLocked()
}

func (p *protectionState) recomputeLocked() {
	previous := p.status.State
	state, reason := "protecting", ""
	p.status.Retryable = false
	if p.status.ApplyID == "" {
		state, reason = "pending", "awaiting configuration"
	} else if p.applying || p.ruleReconciling && !p.installFailed {
		state = "pending"
	} else if p.configured && !p.enabled {
		state = "disabled"
	} else {
		if p.installFailed {
			state, reason = "failed", p.components["nft"].Reason
		}
		for _, c := range p.components {
			if c.Required && c.State != "ready" {
				if c.State == "failed" {
					state = "failed"
					break
				}
				if state != "failed" {
					state = "pending"
				}
			}
		}
		if state != "failed" && p.iecFault != "" && (p.envelope || p.direct || p.policyFault) {
			state, reason = "failed", p.iecFault
		}
		if state == "protecting" {
			if c, ok := p.components["nflog"]; ok && c.State != "off" && c.State != "ready" {
				if c.State == "pending" && !p.nflogLost {
					state, reason = "pending", c.Reason
				} else {
					state, reason = "degraded", "rule-hit logging unavailable"
					p.status.Retryable = true
				}
			}
		}
		if state == "failed" && !p.installFailed {
			for name, c := range p.components {
				if c.Required && c.State == "failed" && (strings.HasPrefix(name, "nfqueue:") || name == "iec-envelope" || name == "scan-gate" && p.gateUnknown) {
					p.status.Retryable = true
				}
			}
		}
		if state == "protecting" || state == "degraded" {
			if c, ok := p.components["interface-attachment"]; ok {
				switch c.State {
				case "unknown":
					state, reason = "unknown", c.Reason
				case "degraded":
					state = "degraded"
					if reason != "" {
						reason += "; "
					}
					reason += c.Reason
				}
			}
		}
	}
	p.status.State = state
	p.status.ObservedAt = time.Now().UTC()
	p.status.Components = make([]ProtectionComponent, 0, len(p.components))
	for name, c := range p.components {
		if name == "iec-envelope" && p.iecFault != "" {
			c.State = "failed"
			c.Reason = p.iecFault
		}
		p.status.Components = append(p.status.Components, c)
	}
	slices.SortFunc(p.status.Components, func(a, b ProtectionComponent) int { return strings.Compare(a.Name, b.Name) })
	if reason == "" {
		// A pending component (notably the closed envelope) must not hide
		// the failed consumer that caused this transition.
		for _, c := range p.status.Components {
			if c.Required && c.State == "failed" && c.Reason != "" {
				reason = c.Reason
				break
			}
		}
	}
	if reason == "" {
		for _, c := range p.status.Components {
			if c.Required && c.State != "ready" && c.Reason != "" {
				reason = c.Reason
				break
			}
		}
	}
	p.status.Effects = []ProtectionEffect{}
	queueReady := p.queue != "" && p.components[p.queue].State == "ready"
	if p.envelope {
		effect := "normal"
		if !queueReady || p.components["iec-envelope"].State != "ready" {
			effect = "fail_closed_drop"
		}
		if p.steeringFault {
			effect = "unknown"
		}
		p.status.Effects = append(p.status.Effects, ProtectionEffect{Traffic: "enforcing IEC 104", Effect: effect})
	}
	if p.direct {
		effect := "normal"
		if !queueReady {
			effect = "not_inspected"
		}
		p.status.Effects = append(p.status.Effects, ProtectionEffect{Traffic: "direct-queue ICS inspection", Effect: effect})
	}
	if p.components["scan-gate"].Required {
		effect := "normal"
		if p.gateUnknown || p.components["scan-gate"].State != "ready" || p.components["scanner"].State != "ready" {
			effect = "unknown"
		}
		p.status.Effects = append(p.status.Effects, ProtectionEffect{Traffic: "selected scan traffic", Effect: effect})
	}
	if previous != state && p.store != nil {
		p.store.Append(events.Event{Kind: "protection.state", Timestamp: p.status.ObservedAt, Attributes: map[string]any{"applyId": p.status.ApplyID, "state": state, "previous": previous, "reason": reason}})
	}
}

// BeginProtection publishes nft pending before configuration or policy changes.
func (e *Engine) BeginProtection(bootID, applyID string) {
	p := e.protection
	p.update(func() {
		p.status.BootID, p.status.ApplyID = bootID, applyID
		p.installFailed = false
		p.applying = true
		p.setLocked("nft", "pending", "application in progress", 0, 0)
		c := p.components["nft"]
		c.Required = true
		p.components["nft"] = c
	})
}

func (e *Engine) Protection() ProtectionStatus {
	p := e.protection
	p.mu.Lock()
	observe := p.serviceOutcomes
	p.mu.Unlock()
	var services []protection.OwnerOutcome
	if observe != nil {
		services = observe()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.status
	st.ObservedAt = time.Now().UTC()
	st.Components = slices.Clone(st.Components)
	st.Effects = slices.Clone(st.Effects)
	if st.Installed != nil {
		ack := *st.Installed
		st.Installed = &ack
	}
	st.Subsystems = p.outcomeSnapshotLocked()
	if observe != nil {
		// These owners' live ledgers are authoritative even when an unlabelled
		// mutation or Stop removed their identity. Never resurrect a copied ack.
		st.Subsystems = slices.DeleteFunc(st.Subsystems, func(out protection.OwnerOutcome) bool {
			return out.Name == protection.SubsystemAV || out.Name == protection.SubsystemWireGuard || out.Name == protection.SubsystemDHCP
		})
	}
	for _, out := range services {
		replaced := false
		for i := range st.Subsystems {
			if st.Subsystems[i].Name == out.Name {
				st.Subsystems[i] = cloneProtectionOutcome(out)
				replaced = true
				break
			}
		}
		if !replaced && out.Name != "" {
			st.Subsystems = append(st.Subsystems, cloneProtectionOutcome(out))
		}
		if out.Retryable {
			st.Retryable = true
		}
	}
	slices.SortFunc(st.Subsystems, func(a, b protection.OwnerOutcome) int { return strings.Compare(string(a.Name), string(b.Name)) })

	return st
}

func (p *protectionState) current(epoch uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.epoch == epoch
}

func (p *protectionState) source(epoch uint64, group uint16, ev capture.SourceEvent) {
	if group == 0 {
		return
	}
	p.update(func() {
		if p.epoch != epoch {
			return
		}
		name := fmt.Sprintf("nfqueue:%d", group)
		state, reason := "pending", name+": source unavailable"
		if ev.Ready {
			state, reason = "ready", ""
		} else if ev.Err != nil {
			reason = name + ": " + ev.Err.Error()
		}
		if ev.Terminal {
			state = "failed"
		}
		p.setLocked(name, state, reason, ev.Attempt, ev.MaxAttempts)
	})
}

func (p *protectionState) bindAttempt(epoch uint64, group uint16, err error, attempt, max int) {
	if group == 0 {
		return
	}
	p.update(func() {
		if p.epoch != epoch || err == nil {
			return
		}
		state := "pending"
		if attempt == max {
			state = "failed"
		}
		name := fmt.Sprintf("nfqueue:%d", group)
		p.setLocked(name, state, name+": "+err.Error(), attempt, max)
	})
}

// SetScanProtection records actual gate admission separately from scanner readiness.
// An explicitly disabled scanner is off; readiness errors while enabled remain pending.
func (e *Engine) SetScanProtection(gateState, gateReason string, scannerEnabled, scannerReady bool, scannerReason string, unknown bool) {
	p := e.protection
	p.update(func() {
		p.gateUnknown = unknown
		p.setLocked("scan-gate", gateState, gateReason, 0, 0)
		state := "pending"
		switch {
		case !scannerEnabled:
			state, scannerReason = "off", ""
		case scannerReady:
			state = "ready"
			scannerReason = ""
		}
		p.setLocked("scanner", state, scannerReason, 0, 0)
	})
}

// SetProtectionBootID sets process identity before admitting the first apply.
func (e *Engine) SetProtectionBootID(id string) {
	e.protection.update(func() { e.protection.status.BootID = id })
}

// ObserveServiceDelivery projects the AV, WireGuard and DHCP owner ledgers without retaining copied
// apply-time proofs. The callback must not call back into the engine; it runs
// outside the protection lock and must return detached owner observations.
func (e *Engine) ObserveServiceDelivery(observe func() []protection.OwnerOutcome) {
	e.protection.mu.Lock()
	defer e.protection.mu.Unlock()
	e.protection.serviceOutcomes = observe
}
