// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package signatures

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

// maxThresholdKeys bounds the per-flow counters of threshold signatures.
const maxThresholdKeys = 4096

// Threshold turns a signature into a rate signature: it alerts once when
// Count qualifying observations of one flow scope fall inside one window,
// and not again until that window has passed. Durations are whole seconds in
// JSON, as in the rest of the config and API (ttlSeconds, intervalSeconds,
// rotateSeconds).
type Threshold struct {
	Count         int `json:"count"`
	WindowSeconds int `json:"windowSeconds"`
}

// Window returns the threshold window.
func (t Threshold) Window() time.Duration {
	return time.Duration(t.WindowSeconds) * time.Second
}

// validate rejects a threshold that could never count: a silently ignored
// threshold would alert on every match instead.
func (t Threshold) validate() error {
	if t.Count < 2 {
		return errors.New("threshold count must be at least 2")
	}
	if t.WindowSeconds < 1 {
		return errors.New("threshold windowSeconds must be at least 1")
	}
	return nil
}

type thresholdKey struct{ sigID, flowID string }

type thresholdState struct {
	start     time.Time
	window    time.Duration
	count     int
	fired     bool
	seenAPDUs map[string]struct{}
}

// passThreshold counts a matching event and reports whether the signature
// alerts for it. Signatures without a threshold alert on every match.
// Callers hold e.matchesMu.
func (e *Engine) passThreshold(sig Signature, ev dpi.Event, now time.Time) bool {
	t := sig.Threshold
	if t == nil || t.validate() != nil {
		return true
	}
	window := t.Window()
	if e.thresholds == nil {
		e.thresholds = make(map[thresholdKey]*thresholdState)
	}
	flowID := ev.FlowID
	if sig.ID == "ICS-WRITE-STORM" {
		flowID = connectionFlowID(flowID)
	}
	key := thresholdKey{sigID: sig.ID, flowID: flowID}
	st := e.thresholds[key]
	if st == nil || now.Sub(st.start) > window {
		if st == nil && len(e.thresholds) >= maxThresholdKeys {
			e.evictThresholds(now)
		}
		st = &thresholdState{start: now, window: window}
		e.thresholds[key] = st
	}
	if st.fired {
		return false
	}
	if sig.ID == "ICS-WRITE-STORM" {
		if apduID := eventAPDUID(ev); apduID != "" {
			if st.seenAPDUs == nil {
				st.seenAPDUs = make(map[string]struct{})
			}
			if _, seen := st.seenAPDUs[apduID]; seen {
				return false
			}
			st.seenAPDUs[apduID] = struct{}{}
		}
	}
	st.count++
	if st.count < t.Count {
		return false
	}
	st.fired = true
	st.seenAPDUs = nil
	return true
}

// connectionFlowID removes the direction bit from the flow.Key.Hash format
// used by ICS decoders and puts reverse tuples in opener-to-server order.
// Other FlowID formats are left unchanged.
func connectionFlowID(flowID string) string {
	parts := strings.Split(flowID, "|")
	if len(parts) != 6 || (parts[5] != "0" && parts[5] != "1") {
		return flowID
	}
	if net.ParseIP(parts[0]) == nil || net.ParseIP(parts[1]) == nil {
		return flowID
	}
	if _, err := strconv.ParseUint(parts[2], 10, 16); err != nil {
		return flowID
	}
	if _, err := strconv.ParseUint(parts[3], 10, 16); err != nil {
		return flowID
	}
	if _, err := strconv.ParseUint(parts[4], 10, 8); err != nil {
		return flowID
	}
	if parts[5] == "1" {
		parts[0], parts[1] = parts[1], parts[0]
		parts[2], parts[3] = parts[3], parts[2]
	}
	return strings.Join(parts[:5], "|")
}

// eventAPDUID identifies IEC 104 object events emitted from one APDU.
func eventAPDUID(ev dpi.Event) string {
	if ev.Attributes == nil {
		return ""
	}
	id, _ := ev.Attributes["apdu_id"].(string)
	return id
}

// evictThresholds drops expired windows, and every window if none expired,
// to keep the counters bounded.
func (e *Engine) evictThresholds(now time.Time) {
	for k, st := range e.thresholds {
		if now.Sub(st.start) > st.window {
			delete(e.thresholds, k)
		}
	}
	if len(e.thresholds) >= maxThresholdKeys {
		e.thresholds = make(map[thresholdKey]*thresholdState)
	}
}
