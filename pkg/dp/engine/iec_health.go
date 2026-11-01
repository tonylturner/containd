// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"sort"
	"strings"
	"sync"
)

// IEC104Enforcement is the iec104Enforcement health object.
type IEC104Enforcement struct {
	Active  bool   `json:"active"`
	Healthy bool   `json:"healthy"`
	Reason  string `json:"reason"`
}

// Enforcement fault causes.
const (
	faultQueue     = "queue"
	faultVerdict   = "verdict"
	faultReset     = "reset"
	faultInjector  = "injector"
	faultWorker    = "worker"
	faultFraming   = "framing"
	faultEnvelope  = "envelope"
	faultSteering  = "steering"
	faultAdmission = "admission_sweep"
	faultGateZones = "gate_zone_sweep"
	faultAddresses = "local_addresses"
)

// transientFaults clear when the inline source reports ready again; the
// others (injector, framing) hold for the life of the configuration.
var transientFaults = []string{faultQueue, faultVerdict, faultReset, faultWorker}

// iecHealth tracks IEC104 enforcement health. Faults are recorded whether
// or not an enforce envelope is loaded; they make the object unhealthy only
// while one is (active describes the loaded runtime envelope). The reset
// injector also closes denied or uninspectable inline ICS connections
// (closeDeniedTCP), so while an enforce rule of another ICS protocol is
// loaded (ics) a reset fault makes the object unhealthy too, with active
// still false.
type iecHealth struct {
	changed   func()
	mu        sync.Mutex
	active    bool
	ics       bool
	faults    map[string]string
	unhealthy bool // enforce_unhealthy was emitted and not yet followed by enforce_healthy
	emit      func(outcome, errText string)
}

func newIECHealth(emit func(outcome, errText string)) *iecHealth {
	return &iecHealth{faults: make(map[string]string), emit: emit}
}

// status returns the current enforcement health.
func (h *iecHealth) status() IEC104Enforcement {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, cause := range []string{faultAdmission, faultGateZones, faultAddresses} {
		if reason, ok := h.faults[cause]; ok {
			return IEC104Enforcement{Active: h.active, Healthy: false, Reason: reason}
		}
	}
	if h.active && len(h.faults) > 0 {
		return IEC104Enforcement{Active: true, Healthy: false, Reason: h.reasonLocked()}
	}
	if reason, ok := h.faults[faultReset]; ok && h.ics {
		return IEC104Enforcement{Active: h.active, Healthy: false, Reason: reason}
	}
	return IEC104Enforcement{Active: h.active, Healthy: true}
}

// injectorReady reports whether resets can be sent.
func (h *iecHealth) injectorReady() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, down := h.faults[faultInjector]
	return !down
}

func (h *iecHealth) reasonLocked() string {
	causes := make([]string, 0, len(h.faults))
	for c := range h.faults {
		causes = append(causes, c)
	}
	sort.Strings(causes)
	parts := make([]string, 0, len(causes))
	for _, c := range causes {
		parts = append(parts, h.faults[c])
	}
	return strings.Join(parts, "; ")
}

// setActive records whether the loaded runtime has an enforce envelope.
func (h *iecHealth) setActive(active bool) {
	h.mu.Lock()
	h.active = active
	outcome, reason := h.transitionLocked()
	h.mu.Unlock()
	h.report(outcome, reason)
}

// setICS records whether the loaded runtime has an enforce rule of an ICS
// protocol other than IEC104. It changes status only, not the
// enforce_healthy/enforce_unhealthy events, which describe IEC104
// envelopes.
func (h *iecHealth) setICS(ics bool) {
	h.mu.Lock()
	h.ics = ics
	h.mu.Unlock()
	h.notify()
}

// fault records a failure of cause with a human reason.
func (h *iecHealth) fault(cause, reason string) {
	h.mu.Lock()
	h.faults[cause] = reason
	outcome, text := h.transitionLocked()
	h.mu.Unlock()
	h.report(outcome, text)
}

// clear removes one fault, for example the envelope disagreement when a new
// policy loads.
func (h *iecHealth) clear(cause string) {
	h.mu.Lock()
	delete(h.faults, cause)
	outcome, text := h.transitionLocked()
	h.mu.Unlock()
	h.report(outcome, text)
}

// sourceReady clears the transient faults: the inline queue is bound and
// delivering again. Recovery occurs only after readiness.
func (h *iecHealth) sourceReady() {
	h.mu.Lock()
	for _, c := range transientFaults {
		delete(h.faults, c)
	}
	outcome, text := h.transitionLocked()
	h.mu.Unlock()
	h.report(outcome, text)
}

// transitionLocked returns the ics.session outcome to emit, if the visible
// health changed.
func (h *iecHealth) transitionLocked() (string, string) {
	bad := h.active && len(h.faults) > 0
	switch {
	case bad && !h.unhealthy:
		h.unhealthy = true
		return outcomeEnforceUnhealthy, h.reasonLocked()
	case !bad && h.unhealthy:
		h.unhealthy = false
		return outcomeEnforceHealthy, ""
	default:
		return "", ""
	}
}

func (h *iecHealth) report(outcome, text string) {
	h.notify()
	if outcome != "" && h.emit != nil {
		h.emit(outcome, text)
	}
}

func (h *iecHealth) observe(changed func()) {
	h.mu.Lock()
	h.changed = changed
	h.mu.Unlock()
}

func (h *iecHealth) notify() {
	h.mu.Lock()
	changed := h.changed
	h.mu.Unlock()
	if changed != nil {
		changed()
	}
}
