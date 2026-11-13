// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package signatures

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

const (
	maxThresholdKeys        = limits.MaxSignatureWindows
	maxThresholdDedupValues = limits.MaxSignatureValues

	thresholdScopeFlow       = "flow"
	thresholdScopeConnection = "connection"
)

// Threshold turns a signature into a rate signature: it alerts once when
// Count qualifying observations of one flow scope fall inside one window,
// and not again until that window has passed. Durations are whole seconds in
// JSON, as in the rest of the config and API (ttlSeconds, intervalSeconds,
// rotateSeconds).
type Threshold struct {
	Count         int    `json:"count"`
	WindowSeconds int    `json:"windowSeconds"`
	Scope         string `json:"scope,omitempty"`
	DedupAttr     string `json:"dedupAttr,omitempty"`
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
	if t.Scope != "" && t.Scope != thresholdScopeFlow && t.Scope != thresholdScopeConnection {
		return fmt.Errorf("threshold scope must be %q or %q", thresholdScopeFlow, thresholdScopeConnection)
	}
	return nil
}

type thresholdKey struct{ sigID, flowID string }

type thresholdState struct {
	start      time.Time
	window     time.Duration
	count      int
	fired      bool
	seen       map[string]struct{}
	valueBytes int
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
	if t.Scope == thresholdScopeConnection {
		if ev.Connection != nil {
			flowID = ev.Connection.Key
		} else if key, ok := flow.ParseKey(flowID); ok {
			if key.Dir == flow.DirReverse {
				key = key.Reversed()
			}
			key.Dir = flow.DirForward
			flowID = key.Hash()
		}
	}
	key := thresholdKey{sigID: sig.ID, flowID: flowID}
	st := e.thresholds[key]
	if st != nil && now.Sub(st.start) > st.window {
		delete(e.thresholds, key)
		st = nil
	}
	if st == nil {
		if len(e.thresholds) >= e.windowLimit() {
			e.evictThresholds(now)
		}
		st = &thresholdState{start: now, window: window}
		e.thresholds[key] = st
		if int64(len(e.thresholds)) > e.thresholdHighWater {
			e.thresholdHighWater = int64(len(e.thresholds))
		}
	}
	if st.fired {
		return false
	}
	if t.DedupAttr != "" {
		if dedupKey, ok := eventDedupKey(ev, t.DedupAttr); ok {
			if _, seen := st.seen[dedupKey]; seen {
				return false
			}
			if len(dedupKey) > e.valueByteLimit() ||
				len(st.seen) >= e.valueLimit() ||
				st.valueBytes+len(dedupKey) > e.valueByteLimit() {
				// Preserve the existing threshold count semantics; only the
				// dedup-history identity is truncated.
				e.resources.Ledger.Record(limits.TableSignatureWindows, limits.ReasonTruncated, limits.ModeObserve)
			} else {
				if st.seen == nil {
					st.seen = make(map[string]struct{})
				}
				st.seen[dedupKey] = struct{}{}
				st.valueBytes += len(dedupKey)
			}
		}
	}
	st.count++
	if st.count < t.Count {
		return false
	}
	st.fired = true
	st.seen = nil
	st.valueBytes = 0
	return true
}

// eventDedupKey serializes a nonempty attribute value for identity comparison.
func eventDedupKey(ev dpi.Event, attr string) (string, bool) {
	if ev.Attributes == nil {
		return "", false
	}
	value, ok := ev.Attributes[attr]
	if !ok || isEmptyDedupValue(value) {
		return "", false
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", false
	}
	return string(encoded), true
}

func isEmptyDedupValue(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.String, reflect.Array, reflect.Slice, reflect.Map:
		return v.Len() == 0
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Pointer:
		return v.IsNil()
	default:
		return false
	}
}

// evictThresholds drops expired windows, then only the oldest live window.
func (e *Engine) evictThresholds(now time.Time) {
	for k, st := range e.thresholds {
		if now.Sub(st.start) > st.window {
			delete(e.thresholds, k)
		}
	}
	if len(e.thresholds) >= e.windowLimit() {
		var oldestKey thresholdKey
		var oldest *thresholdState
		for key, st := range e.thresholds {
			if oldest == nil || st.start.Before(oldest.start) ||
				(st.start.Equal(oldest.start) && (key.sigID < oldestKey.sigID ||
					(key.sigID == oldestKey.sigID && key.flowID < oldestKey.flowID))) {
				oldestKey, oldest = key, st
			}
		}
		if oldest != nil {
			delete(e.thresholds, oldestKey)
			e.resources.Ledger.Record(limits.TableSignatureWindows, limits.ReasonEvicted, limits.ModeObserve)
		}
	}
}

func (e *Engine) windowLimit() int {
	if e.maxWindows <= 0 {
		return maxThresholdKeys
	}
	return min(e.maxWindows, maxThresholdKeys)
}

func (e *Engine) valueLimit() int {
	if e.maxValues <= 0 {
		return maxThresholdDedupValues
	}
	return min(e.maxValues, maxThresholdDedupValues)
}

func (e *Engine) valueByteLimit() int {
	if e.maxValueBytes <= 0 {
		return limits.MaxSignatureValueBytes
	}
	return min(e.maxValueBytes, limits.MaxSignatureValueBytes)
}
