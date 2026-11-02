// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"slices"
	"strings"

	"github.com/tonylturner/containd/pkg/common/protection"
)

func (s ProtectionStatus) metadata() protection.Metadata {
	return protection.Metadata{BootID: protection.BootID(s.BootID), ApplyID: protection.ApplyID(s.ApplyID),
		RunningRevision: s.RunningRevision, Mode: s.Mode}
}

// Observation projects the existing engine observation, not a second health
// version. Installed can still refer to the previous target during convergence.
func (s ProtectionStatus) Observation() protection.EngineObservation {
	return protection.EngineObservation{Metadata: s.metadata(), Installed: s.Installed,
		State: protection.State(s.State), ObservedAt: s.ObservedAt}
}

// BindProtection associates a newly admitted attempt without invalidating an
// installation or adopting any prior owner acknowledgement.
func (e *Engine) BindProtection(m protection.Metadata) {
	e.protection.update(func() {
		p := e.protection
		p.status.BootID, p.status.ApplyID = string(m.BootID), string(m.ApplyID)
		p.status.RunningRevision, p.status.Mode = m.RunningRevision, m.Mode
	})
}

// SetProtectionOutcome accepts completion only for the currently admitted
// attempt. Owners invalidate before mutation, including partial failures.
func (e *Engine) SetProtectionOutcome(m protection.Metadata, o protection.OwnerOutcome) {
	e.protection.update(func() {
		p := e.protection
		if p.status.metadata() != m {
			return
		}
		if o.Acknowledged != nil && o.Acknowledged.Metadata != m {
			return
		}
		p.outcomes[o.Name] = cloneProtectionOutcome(o)
	})
}

func cloneProtectionOutcome(o protection.OwnerOutcome) protection.OwnerOutcome {
	if o.Acknowledged != nil {
		ack := *o.Acknowledged
		o.Acknowledged = &ack
	}
	if o.Fault != nil {
		fault := *o.Fault
		o.Fault = &fault
	}
	if o.NextRetryAt != nil {
		at := *o.NextRetryAt
		o.NextRetryAt = &at
	}
	return o
}

func (p *protectionState) outcomeSnapshotLocked() []protection.OwnerOutcome {
	out := make([]protection.OwnerOutcome, 0, len(p.outcomes)+len(p.components))
	for _, o := range p.outcomes {
		out = append(out, cloneProtectionOutcome(o))
	}
	// Consumer/scanner proofs are live: an apply-time acknowledgement cannot
	// hide subsequent loss. Keep the existing names and policy selection.
	for _, c := range p.status.Components {
		if c.Name != "nft" && c.Name != "iec-envelope" && c.Name != "scan-gate" &&
			c.Name != "scanner" && !strings.HasPrefix(c.Name, "nfqueue:") {
			continue
		}
		o := protection.OwnerOutcome{Name: protection.SubsystemName(c.Name), Owner: protection.OwnerEngine,
			DesiredRevision: p.status.RunningRevision, Operation: protection.OperationApply,
			State: protection.DeliveryState(c.State), Reason: c.Reason, Attempt: c.Attempt,
			ObservedAt: p.status.ObservedAt, Retryable: p.status.Retryable}
		if c.State == "ready" && p.status.metadata().Valid() {
			o.Acknowledged = &protection.Acknowledgement{Metadata: p.status.metadata(), Operation: o.Operation}
			if c.Name == "nft" {
				o.Acknowledged = p.status.Installed
				if o.Acknowledged != nil {
					ack := *o.Acknowledged
					o.Acknowledged = &ack
					o.DesiredRevision = ack.RunningRevision
				}
			}
		}
		if c.State == "failed" {
			o.Fault = &protection.Fault{Kind: protection.FaultDelivery, Reason: c.Reason}
		}
		out = append(out, o)
	}
	slices.SortFunc(out, func(a, b protection.OwnerOutcome) int { return strings.Compare(string(a.Name), string(b.Name)) })
	return out
}
