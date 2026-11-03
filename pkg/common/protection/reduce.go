// SPDX-License-Identifier: Apache-2.0

package protection

import (
	"slices"
	"time"
)

// EngineObservation is a coherent engine-owned observation. Installed is a
// positive policy-install/readback proof, retained across auxiliary retries and
// invalidated only when installation is unprovable. It may name an older target.
// A missing poll must not erase separately known successful synchronous install
// evidence; the caller supplies that retained observation, not invented success.
type EngineObservation struct {
	Metadata
	Installed  *Acknowledgement `json:"installed"`
	State      State            `json:"state"`
	ObservedAt time.Time        `json:"observedAt"`
}

// Input is a detached coherent authority/owner snapshot. The caller rechecks
// desired and trust generation after collection; on a second change it supplies
// Coherent=false. No store locks, clocks, probing or runtime effects live here.
type Input struct {
	DesiredRevision      Revision
	Current              Metadata
	DesiredTrustRevision TrustRevision
	Selection            Selection
	Outcomes             []OwnerOutcome
	Engine               EngineObservation
	Coherent             bool
	EnforcementEnabled   bool
	Uncertain            bool
	Degraded             bool // existing logging/schedule/enforcement overrides
}

// Reduce computes clean protection, never last-ever success. Owner proofs must
// match the desired revision AND current boot/attempt/mode, including teardown.
// Acknowledged older installations remain visible but cannot protect the target.
func Reduce(in Input) Aggregate {
	out := Aggregate{State: StateUnknown, Subsystems: []SubsystemStatus{}}
	if in.DesiredRevision != "" {
		out.DesiredRevision = revisionPointer(in.DesiredRevision)
	}
	statuses, wellFormed := subsystemStatuses(in)
	out.Subsystems = statuses

	if !in.Coherent || !in.Current.Valid() || !validEngine(in) {
		return out
	}
	if !in.EnforcementEnabled || in.Engine.State == StateDisabled {
		out.State = StateDisabled
		return out
	}
	if in.Current.Mode == ModeRecovery {
		return out
	}
	if installed := in.Engine.Installed; installed != nil &&
		installed.Metadata.Valid() && installed.Mode == ModeNormal &&
		installed.BootID == in.Current.BootID && installed.Operation == OperationApply {
		out.AppliedRevision = revisionPointer(installed.RunningRevision)
	}
	if in.Uncertain {
		return out
	}
	if !ValidRunningRevision(in.DesiredRevision) ||
		in.Current.RunningRevision != in.DesiredRevision || !wellFormed {
		return out
	}
	if in.Engine.Metadata != in.Current {
		return out
	}
	if in.Engine.State == StateFailed {
		out.State = StateFailed
		return out
	}
	out.State = StatePending
	allConfirmed := true
	for _, status := range statuses {
		if status.Required && !confirmed(status, in) {
			allConfirmed = false
			if status.State == DeliveryFailed || status.Fault != nil {
				out.State = StateFailed
				return out
			}
		}
	}
	if !allConfirmed {
		return out
	}
	if in.Engine.State == StateDegraded || in.Degraded {
		out.State = StateDegraded
		return out
	}
	if in.Engine.State != StateProtecting || out.AppliedRevision == nil ||
		*out.AppliedRevision != in.DesiredRevision ||
		in.Engine.Installed.Metadata != in.Current {
		return out
	}
	out.ProtectingRevision = revisionPointer(in.DesiredRevision)
	out.Ready, out.State = true, StateProtecting
	return out
}

func validEngine(in Input) bool {
	e := in.Engine
	return e.Metadata.Valid() && e.BootID == in.Current.BootID &&
		!e.ObservedAt.IsZero() && validState(e.State) && e.State != StateUnknown
}

func validState(s State) bool {
	switch s {
	case StatePending, StateProtecting, StateDegraded, StateFailed, StateDisabled, StateUnknown:
		return true
	default:
		return false
	}
}

func confirmed(s SubsystemStatus, in Input) bool {
	ack := s.Acknowledged
	if s.DesiredRevision != in.DesiredRevision || s.Fault != nil ||
		s.ObservedAt.IsZero() || ack == nil || ack.Metadata != in.Current ||
		ack.Operation != s.Operation {
		return false
	}
	if s.Operation != OperationApply && s.Operation != OperationStop {
		return false
	}
	if s.State != DeliveryReady && !(s.State == DeliveryOff && s.Operation == OperationStop) {
		return false
	}
	return s.Name != SubsystemTrust ||
		in.DesiredTrustRevision != "" && ack.TrustRevision == in.DesiredTrustRevision
}

func subsystemStatuses(in Input) ([]SubsystemStatus, bool) {
	rows := Requirements(in.Selection)
	out := make([]SubsystemStatus, 0, len(rows)+len(in.Outcomes))
	byName := make(map[SubsystemName]OwnerOutcome, len(in.Outcomes))
	wellFormed := true
	for _, outcome := range in.Outcomes {
		if _, exists := byName[outcome.Name]; exists {
			wellFormed = false
		}
		byName[outcome.Name] = outcome
	}
	seen := make(map[SubsystemName]bool, len(rows))
	for _, row := range rows {
		if seen[row.Name] || row.Name == NFQueueName(0) {
			wellFormed = false
		}
		seen[row.Name] = true
		outcome, ok := byName[row.Name]
		if !ok {
			outcome = OwnerOutcome{Name: row.Name, Owner: row.Owner,
				DesiredRevision: in.DesiredRevision, State: DeliveryUnknown,
				Reason: "awaiting owner observation"}
		} else if outcome.Owner != row.Owner || !validDeliveryState(outcome.State) ||
			outcome.Operation == OperationStop && !row.AllowStop {
			wellFormed = false
		}
		status := SubsystemStatus{OwnerOutcome: cloneOutcome(outcome), Required: row.Required}
		if row.Name == SubsystemTrust {
			status.DesiredTrustRevision = in.DesiredTrustRevision
		}
		out = append(out, status)
		delete(byName, row.Name)
	}
	// Unexpected owner names remain visible, but never silently broaden or
	// bypass the fixed table. Reject ambiguous snapshots rather than guessing.
	for _, outcome := range byName {
		wellFormed = false
		out = append(out, SubsystemStatus{OwnerOutcome: cloneOutcome(outcome)})
	}
	slices.SortFunc(out, func(a, b SubsystemStatus) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return out, wellFormed
}

func validDeliveryState(s DeliveryState) bool {
	switch s {
	case DeliveryPending, DeliveryReady, DeliveryFailed, DeliveryOff, DeliveryUnknown:
		return true
	default:
		return false
	}
}

func cloneOutcome(o OwnerOutcome) OwnerOutcome {
	if o.Acknowledged != nil {
		ack := *o.Acknowledged
		o.Acknowledged = &ack
	}
	if o.Fault != nil {
		fault := *o.Fault
		o.Fault = &fault
	}
	if o.NextRetryAt != nil {
		next := *o.NextRetryAt
		o.NextRetryAt = &next
	}
	return o
}

func revisionPointer(r Revision) *Revision { return &r }
