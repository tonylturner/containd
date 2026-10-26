// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package signatures

import (
	"errors"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

// maxThresholdKeys bounds the per-flow counters of threshold signatures.
const maxThresholdKeys = 4096

// Threshold turns a signature into a rate signature: it alerts once when
// Count matching events of one flow fall inside one window of
// WindowSeconds, and not again until that window has passed. Durations are
// whole seconds in JSON, as in the rest of the config and API
// (ttlSeconds, intervalSeconds, rotateSeconds).
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
	start  time.Time
	window time.Duration
	count  int
	fired  bool
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
	key := thresholdKey{sigID: sig.ID, flowID: ev.FlowID}
	st := e.thresholds[key]
	if st == nil || now.Sub(st.start) > window {
		if st == nil && len(e.thresholds) >= maxThresholdKeys {
			e.evictThresholds(now)
		}
		st = &thresholdState{start: now, window: window}
		e.thresholds[key] = st
	}
	st.count++
	if st.fired || st.count < t.Count {
		return false
	}
	st.fired = true
	return true
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
