// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"time"

	"github.com/gin-gonic/gin"
	engineclient "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/app/convergence"
	"github.com/tonylturner/containd/pkg/common/protection"
)

const runtimeContextKey = "runtimeConvergence"

func requestCoordinator(c *gin.Context) (convergence.Coordinator, bool) {
	value, _ := c.Get(runtimeContextKey)
	coordinator, ok := value.(convergence.Coordinator)
	if !ok {
		apiError(c, http.StatusServiceUnavailable, "runtime coordinator unavailable")
	}
	return coordinator, ok
}

// authenticatedProtection preserves raw engine fields while replacing state
// and subsystems with the revision-bound aggregate. Packet effects remain
// exclusively engine observations.
func authenticatedProtection(ctx context.Context, coordinator convergence.Coordinator, engine EngineClient) (gin.H, error) {
	st := engineclient.UnknownProtection("")
	hc, supported := engine.(RuntimeHealthClient)
	var observationErr error
	if supported {
		health, err := hc.RuntimeHealth(ctx)
		observationErr = err
		if err == nil && health.Protection.BootID == health.BootID {
			st = engineclient.NormalizeProtection(health.Protection, "")
		}
	} else {
		observationErr = errors.New("engine health unavailable")
	}
	aggregate, err := coordinator.Status(ctx)
	if err != nil || observationErr != nil {
		aggregate.Ready, aggregate.ProtectingRevision = false, nil
		aggregate.State = protection.StateUnknown
	}
	if supported && observationErr == nil {
		latest, readErr := hc.RuntimeHealth(ctx)
		if readErr != nil || latest.BootID != st.BootID || latest.Protection.ApplyID != st.ApplyID ||
			latest.Protection.RunningRevision != st.RunningRevision || latest.Protection.Mode != st.Mode ||
			latest.Protection.State != st.State || !reflect.DeepEqual(latest.Protection.Installed, st.Installed) ||
			!sameOwnerProofs(latest.Protection.Subsystems, st.Subsystems) {
			aggregate.Ready, aggregate.ProtectingRevision = false, nil
			aggregate.State = protection.StateUnknown
			observationErr = errors.Join(readErr, errors.New("engine observation changed"))
		}
	}
	if aggregate.Subsystems == nil {
		aggregate.Subsystems = []protection.SubsystemStatus{}
	}
	return gin.H{
		"bootId": st.BootID, "applyId": st.ApplyID, "installedApplyId": st.InstalledApplyID,
		"runningRevision": st.RunningRevision, "mode": st.Mode, "installed": st.Installed,
		"observedAt": st.ObservedAt, "components": st.Components, "effects": st.Effects,
		"retryable": st.Retryable, "state": aggregate.State,
		"desiredRevision": aggregate.DesiredRevision, "appliedRevision": aggregate.AppliedRevision,
		"protectingRevision": aggregate.ProtectingRevision, "ready": aggregate.Ready,
		"subsystems": aggregate.Subsystems,
	}, errors.Join(err, observationErr)
}

// Observation timestamps advance on each read. Identity, completion and faults
// must nevertheless remain coherent across raw and aggregate collection.
func sameOwnerProofs(a, b []protection.OwnerOutcome) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		left, right := a[i], b[i]
		left.ObservedAt, right.ObservedAt = time.Time{}, time.Time{}
		if !reflect.DeepEqual(left, right) {
			return false
		}
	}
	return true
}

func transitionResponse(c *gin.Context, coordinator convergence.Coordinator, engine EngineClient, result convergence.Result) gin.H {
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Second)
	defer cancel()
	view, _ := authenticatedProtection(ctx, coordinator, engine)
	return gin.H{"runningRevision": result.RunningRevision, "applyId": result.ApplyID, "protection": view}
}

// Human diagnostics accompany, but never replace, the labelled owner ledger.
// Only sanitized typed faults are reflected into warning headers.
func deliveryWarnings(ctx context.Context, coordinator convergence.Coordinator, initial []string) []string {
	status, _ := coordinator.Status(ctx)
	out := append([]string(nil), initial...)
	for _, subsystem := range status.Subsystems {
		if subsystem.Fault != nil {
			out = append(out, string(subsystem.Name)+": "+subsystem.Fault.Reason)
		}
	}
	return out
}
