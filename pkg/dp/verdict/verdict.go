// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package verdict

import (
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Action describes how the data plane should treat a flow or asset.
type Action string

const (
	AllowContinue Action = "ALLOW_CONTINUE"
	DenyDrop      Action = "DENY_DROP"
	// DenyReset is a RESET rule's decision. nftables rejects back to the
	// sender; the engine, which cannot reject a queued packet, drops it
	// like DenyDrop.
	DenyReset     Action = "DENY_RESET"
	AlertOnly     Action = "ALERT_ONLY"
	BlockFlowTemp Action = "BLOCK_FLOW_TEMP"
	BlockHostTemp Action = "BLOCK_HOST_TEMP"
)

// Verdict is produced by the evaluator/DPI/IDS and consumed by enforcement.
type Verdict struct {
	Action Action        `json:"action"`
	Reason string        `json:"reason,omitempty"`
	TTL    time.Duration `json:"ttl,omitempty"`
}

// FromRulesAction maps a rule decision to a baseline verdict. Only ALLOW
// admits; every other action, including the RATE_LIMIT and TAG effects
// that never decide, maps to a denial.
func FromRulesAction(a rules.Action) Verdict {
	switch a {
	case rules.ActionAllow:
		return Verdict{Action: AllowContinue}
	case rules.ActionReset:
		return Verdict{Action: DenyReset}
	default:
		return Verdict{Action: DenyDrop}
	}
}

// Denies reports whether the verdict's action is a DENY or RESET decision.
func (v Verdict) Denies() bool {
	return v.Action == DenyDrop || v.Action == DenyReset
}
