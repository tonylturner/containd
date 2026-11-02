// SPDX-License-Identifier: Apache-2.0

package protection

import "time"

type Owner string

const (
	OwnerEngine     Owner = "engine"
	OwnerManagement Owner = "management"
)

type DeliveryState string

const (
	DeliveryPending DeliveryState = "pending"
	DeliveryReady   DeliveryState = "ready"
	DeliveryFailed  DeliveryState = "failed"
	DeliveryOff     DeliveryState = "off"
	DeliveryUnknown DeliveryState = "unknown"
)

type Operation string

const (
	OperationApply Operation = "apply"
	OperationStop  Operation = "stop"
)

type FaultKind string

const (
	FaultConfig   FaultKind = "config"
	FaultRender   FaultKind = "render"
	FaultDelivery FaultKind = "delivery"
	FaultUnknown  FaultKind = "unknown"
)

// Fault contains owner-sanitized diagnostics, never raw secret-bearing errors.
// Config/render faults block the relevant input; delivery faults can retry.
type Fault struct {
	Kind   FaultKind `json:"kind"`
	Reason string    `json:"reason"`
}

// Acknowledgement is emitted only after owner completion or positive readback.
// Stop acknowledges verified absence, not merely a desired disabled value.
// TrustRevision is populated for trust, including verified clear ("none").
type Acknowledgement struct {
	Metadata
	Operation     Operation     `json:"operation"`
	TrustRevision TrustRevision `json:"trustRevision,omitempty"`
}

// OwnerOutcome is the current owner observation. Before ANY mutating attempt,
// the owner must invalidate its old acknowledgement, even if that attempt fails.
// Adoption into another attempt requires unbroken positive readback, not token
// equality. Current live scanner/consumer faults must replace earlier success.
// ObservedAt is evidence presence, never a clock-based identity ordering fence.
type OwnerOutcome struct {
	Name            SubsystemName    `json:"name"`
	Owner           Owner            `json:"owner"`
	DesiredRevision Revision         `json:"desiredRevision"`
	Operation       Operation        `json:"operation"`
	State           DeliveryState    `json:"state"`
	Acknowledged    *Acknowledgement `json:"acknowledged"`
	Fault           *Fault           `json:"fault"`
	Reason          string           `json:"reason"`
	Attempt         int              `json:"attempt"`
	NextRetryAt     *time.Time       `json:"nextRetryAt"`
	ObservedAt      time.Time        `json:"observedAt"`
	Retryable       bool             `json:"retryable"`
}

// SubsystemStatus adds the table-derived requirement and trust dependency.
// Required is output-only: callers cannot choose their own gating flags.
type SubsystemStatus struct {
	OwnerOutcome
	Required             bool          `json:"required"`
	DesiredTrustRevision TrustRevision `json:"desiredTrustRevision,omitempty"`
}

type State string

const (
	StatePending    State = "pending"
	StateProtecting State = "protecting"
	StateDegraded   State = "degraded"
	StateFailed     State = "failed"
	StateDisabled   State = "disabled"
	StateUnknown    State = "unknown"
)

// Aggregate is embedded into the authenticated protection response alongside
// engine-owned IDs/components/effects. Absent revisions encode as JSON null;
// subsystems always encodes as an array. It contains no inferred packet effects.
type Aggregate struct {
	DesiredRevision    *Revision         `json:"desiredRevision"`
	AppliedRevision    *Revision         `json:"appliedRevision"`
	ProtectingRevision *Revision         `json:"protectingRevision"`
	Ready              bool              `json:"ready"`
	State              State             `json:"state"`
	Subsystems         []SubsystemStatus `json:"subsystems"`
}
