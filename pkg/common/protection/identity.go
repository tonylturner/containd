// SPDX-License-Identifier: Apache-2.0

// Package protection defines revision-bound delivery values and the pure
// protection reducer. It owns no configuration, transport or runtime lifecycle.
package protection

import "strings"

// Header names are shared by every configuration-affecting engine phase.
// PreviousApplyIDHeader must be present (even when empty) on first admission.
const (
	ApplyIDHeader         = "X-Containd-Apply-Id"
	EngineBootIDHeader    = "X-Containd-Engine-Boot-Id"
	RunningRevisionHeader = "X-Containd-Running-Revision"
	ApplyModeHeader       = "X-Containd-Apply-Mode"
	PreviousApplyIDHeader = "X-Containd-Previous-Apply-Id"
	MaxTokenLength        = 64
)

type BootID string
type ApplyID string

// Revision names either a persisted running generation or a reserved recovery
// target. Recovery targets must never be persisted as running generations.
// Tokens are opaque, equality-only values, independent of CAS and apply IDs.
type Revision string

// TrustRevision is the existing bundle revision, including "none" for clear.
// Empty means unknown, not a successfully cleared bundle.
type TrustRevision string

type ApplyMode string

const (
	ModeNormal   ApplyMode = "normal"
	ModeRecovery ApplyMode = "recovery"
)

// Metadata binds an attempt to a boot and immutable target. Acknowledgements
// embed this shape; predecessor is admission-only, not acknowledgement state.
type Metadata struct {
	BootID          BootID    `json:"bootId"`
	ApplyID         ApplyID   `json:"applyId"`
	RunningRevision Revision  `json:"runningRevision"`
	Mode            ApplyMode `json:"mode"`
}

// Admission adds the manager-observed predecessor, compared atomically by the
// engine only when admitting a new apply ID. Empty is valid on a fresh boot.
type Admission struct {
	Metadata
	PreviousApplyID ApplyID `json:"previousApplyId"`
}

// RecoveryRevision returns the reserved engine target for a boot.
func RecoveryRevision(boot BootID) Revision { return Revision("recovery:" + boot) }

// ValidRunningRevision excludes the reserved recovery namespace. Tokens use the
// URL-safe opaque alphabet and are bounded; minting belongs to the store.
func ValidRunningRevision(r Revision) bool { return validToken(string(r)) }

// Valid checks scalar identity only, not predecessor admission or owner proof.
func (m Metadata) Valid() bool {
	if !validToken(string(m.BootID)) || !validToken(string(m.ApplyID)) {
		return false
	}
	switch m.Mode {
	case ModeNormal:
		return ValidRunningRevision(m.RunningRevision)
	case ModeRecovery:
		return m.RunningRevision == RecoveryRevision(m.BootID)
	default:
		return false
	}
}

func validToken(s string) bool {
	if len(s) == 0 || len(s) > MaxTokenLength {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' || r == '-' || r == '_')
	}) == -1
}
