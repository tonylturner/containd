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
	DenyReset     Action = "DENY_RESET"
	AlertOnly     Action = "ALERT_ONLY"
	BlockFlowTemp Action = "BLOCK_FLOW_TEMP"
	BlockHostTemp Action = "BLOCK_HOST_TEMP"
	RateLimitFlow Action = "RATE_LIMIT_FLOW"
	TagFlow       Action = "TAG_FLOW"
)

// Verdict is produced by the evaluator/DPI/IDS and consumed by enforcement.
type Verdict struct {
	Action Action        `json:"action"`
	Reason string        `json:"reason,omitempty"`
	TTL    time.Duration `json:"ttl,omitempty"`
	Tags   []string      `json:"tags,omitempty"`
}

// FromRulesAction maps a simple rules.Action to a baseline verdict.
func FromRulesAction(a rules.Action) Verdict {
	switch a {
	case rules.ActionAllow:
		return Verdict{Action: AllowContinue}
	case rules.ActionDeny:
		return Verdict{Action: DenyDrop}
	default:
		return Verdict{Action: DenyDrop}
	}
}

