// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"crypto/rand"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/events"
)

// ProtectionStatus is an engine-owned observation, not an apply acknowledgement.
// It is shared with the engine API client; slices returned by Protection are copies.
type ProtectionStatus struct {
	BootID           string                `json:"bootId"`
	ApplyID          string                `json:"applyId"`
	InstalledApplyID string                `json:"installedApplyId"`
	State            string                `json:"state"`
	Retryable        bool                  `json:"retryable"`
	ObservedAt       time.Time             `json:"observedAt"`
	Components       []ProtectionComponent `json:"components"`
	Effects          []ProtectionEffect    `json:"effects"`
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
	store            *events.Store
}

func newProtection(store *events.Store) *protectionState {
	p := &protectionState{store: store, components: map[string]ProtectionComponent{}}
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
		if state == "degraded" {
			p.status.Retryable = true
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

// BeginProtection publishes pending before an apply changes any runtime service.
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
	defer p.mu.Unlock()
	st := p.status
	st.ObservedAt = time.Now().UTC()
	st.Components = slices.Clone(st.Components)
	st.Effects = slices.Clone(st.Effects)
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
func (e *Engine) SetScanProtection(gateState, gateReason string, scannerReady bool, scannerReason string, unknown bool) {
	p := e.protection
	p.update(func() {
		p.gateUnknown = unknown
		p.setLocked("scan-gate", gateState, gateReason, 0, 0)
		state := "pending"
		if scannerReady {
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
