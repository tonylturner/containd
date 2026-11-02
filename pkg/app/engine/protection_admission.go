// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
)

func readAdmission(w http.ResponseWriter, r *http.Request) (protection.Admission, bool) {
	a := protection.Admission{Metadata: protection.Metadata{
		BootID:          protection.BootID(r.Header.Get(protection.EngineBootIDHeader)),
		ApplyID:         protection.ApplyID(r.Header.Get(protection.ApplyIDHeader)),
		RunningRevision: protection.Revision(r.Header.Get(protection.RunningRevisionHeader)),
		Mode:            protection.ApplyMode(r.Header.Get(protection.ApplyModeHeader)),
	}, PreviousApplyID: protection.ApplyID(r.Header.Get(protection.PreviousApplyIDHeader))}
	if !a.Metadata.Valid() {
		protectionError(w, http.StatusBadRequest, "invalid_apply_identity", "valid boot, apply, running revision and mode headers are required")
		return a, false
	}
	if a.BootID != protection.BootID(engineBootID) {
		protectionError(w, http.StatusConflict, "engine_boot_changed", "engine boot changed")
		return a, false
	}
	return a, true
}

type phaseCompletion struct {
	c *protectionCoordinator
	m protection.Metadata
}

type completionKey struct{}

// resolvedPhaseInput runs under admission's effect lock, after the owner has
// resolved logical bindings but before any mutation. Re-resolving a changed
// projection is not a same-input retry.
func resolvedPhaseInput(w http.ResponseWriter, r *http.Request, phase string, value any) bool {
	completion, ok := r.Context().Value(completionKey{}).(phaseCompletion)
	if !ok {
		return true
	}
	body, err := json.Marshal(value)
	if err != nil {
		protectionError(w, http.StatusBadRequest, "invalid_phase_input", "invalid resolved phase input")
		return false
	}
	c := completion.c
	key := phase + ":resolved"
	if previous, exists := c.inputs[key]; exists && previous != string(body) {
		protectionError(w, http.StatusConflict, "apply_input_changed", "changed resolved phase input requires a new apply ID")
		return false
	}
	c.inputs[key] = string(body)
	return true
}

func ownerCompletion(r *http.Request, name protection.SubsystemName, enabled bool, err error) {
	if completion, ok := r.Context().Value(completionKey{}).(phaseCompletion); ok {
		completion.c.outcome(completion.m, name, enabled, true, err != nil, "")
	}
}

func (c *protectionCoordinator) outcome(m protection.Metadata, name protection.SubsystemName, enabled, done, failed bool, trust protection.TrustRevision) {
	o := protection.OwnerOutcome{Name: name, Owner: protection.OwnerEngine, DesiredRevision: m.RunningRevision,
		Operation: protection.OperationApply, State: protection.DeliveryPending, ObservedAt: time.Now().UTC()}
	if !enabled {
		o.Operation = protection.OperationStop
	}
	if done {
		o.State = protection.DeliveryReady
		if !enabled {
			o.State = protection.DeliveryOff
		}
		o.Acknowledged = &protection.Acknowledgement{Metadata: m, Operation: o.Operation, TrustRevision: trust}
	}
	if failed {
		o.State, o.Acknowledged, o.Retryable = protection.DeliveryFailed, nil, true
		o.Fault = &protection.Fault{Kind: protection.FaultDelivery, Reason: "owner apply failed"}
	}
	c.dp.SetProtectionOutcome(m, o)
}

// phaseWriter observes the handler's result without buffering or replacing its
// protocol response. A failed partial mutation never retains the old proof.
type phaseWriter struct {
	http.ResponseWriter
	status int
}

func (w *phaseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *phaseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// admit extends the existing current/seen fence. Per-phase inputs are local
// immutable comparisons, not material digests or an additional plan protocol.
func (c *protectionCoordinator) admit(phase string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next(w, r)
			return
		}
		a, ok := readAdmission(w, r)
		if !ok {
			return
		}
		arrived := c.now()
		// Bound and canonicalize the phase locally, before taking the effect
		// lock. UseNumber avoids losing opaque numeric policy values.
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32<<20))
		var value any
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		if err != nil || decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
			protectionError(w, http.StatusBadRequest, "invalid_phase_input", "invalid JSON phase input")
			return
		}
		canonical, err := json.Marshal(value)
		if err != nil {
			protectionError(w, http.StatusBadRequest, "invalid_phase_input", "invalid JSON phase input")
			return
		}
		input := r.URL.Query().Encode() + "\n" + string(canonical)
		r.Body = io.NopCloser(bytes.NewReader(body))
		c.mu.Lock()
		defer c.mu.Unlock()
		now := c.now()
		if r.Context().Err() != nil || now.Sub(arrived) >= applyReplayWindow {
			protectionError(w, http.StatusRequestTimeout, "apply_expired", "application request expired before admission")
			return
		}
		if c.closed {
			protectionError(w, http.StatusServiceUnavailable, "engine_stopping", "engine stopping")
			return
		}
		id := string(a.ApplyID)
		for old, superseded := range c.seen {
			if now.Sub(superseded) >= applyReplayWindow {
				delete(c.seen, old)
			}
		}
		if _, seen := c.seen[id]; seen {
			protectionError(w, http.StatusConflict, "apply_superseded", "application was superseded")
			return
		}
		if id == c.current && a.Metadata != c.metadata {
			protectionError(w, http.StatusConflict, "apply_target_changed", "application target is immutable")
			return
		}
		if id != c.current {
			if _, present := r.Header[http.CanonicalHeaderKey(protection.PreviousApplyIDHeader)]; !present ||
				string(a.PreviousApplyID) != c.current {
				protectionError(w, http.StatusConflict, "apply_predecessor_changed", "application predecessor changed")
				return
			}
		}
		if a.Mode == protection.ModeRecovery {
			if r.URL.Query().Get("mode") != "" {
				protectionError(w, http.StatusConflict, "invalid_recovery_phase", "recovery cannot replace network state")
				return
			}
			if !c.recoveryPhase(w, phase, body, id == c.current) {
				return
			}
		}
		if id != c.current {
			if c.current != "" {
				c.seen[c.current] = now
			}
			c.current, c.metadata = id, a.Metadata
			c.inputs, c.completed = map[string]string{}, map[string]bool{}
			c.dp.BindProtection(a.Metadata)
		}
		if previous, exists := c.inputs[phase]; exists && previous != input {
			protectionError(w, http.StatusConflict, "apply_input_changed", "changed phase input requires a new apply ID")
			return
		}
		c.inputs[phase] = input
		name := protection.SubsystemName(phase)
		if phase != "services" && phase != "nft" {
			c.outcome(a.Metadata, name, true, false, false, "")
		}
		if phase == "services" {
			c.outcome(a.Metadata, protection.SubsystemWireGuard, true, false, false, "")
			c.outcome(a.Metadata, protection.SubsystemDHCP, true, false, false, "")
		}
		if phase == "interfaces" {
			c.outcome(a.Metadata, protection.SubsystemForwarding, true, false, false, "")
		}
		r = r.WithContext(context.WithValue(r.Context(), completionKey{}, phaseCompletion{c, a.Metadata}))
		result := &phaseWriter{ResponseWriter: w}
		next(result, r)
		success := result.status == 0 || result.status < 300
		c.completed[phase] = success
		if phase != "services" && phase != "nft" {
			var trustRevision protection.TrustRevision
			if phase == "trust" && success {
				var bundle struct{ Revision string }
				_ = json.Unmarshal(body, &bundle)
				trustRevision = protection.TrustRevision(bundle.Revision)
			}
			c.outcome(a.Metadata, name, true, success, !success, trustRevision)
		}
	}
}
