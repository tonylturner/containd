// SPDX-License-Identifier: Apache-2.0

package convergence

import (
	"context"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func cloneOutcomes(in []protection.OwnerOutcome) []protection.OwnerOutcome {
	out := append([]protection.OwnerOutcome(nil), in...)
	for i := range out {
		if out[i].Acknowledged != nil {
			ack := *out[i].Acknowledged
			out[i].Acknowledged = &ack
		}
		if out[i].Fault != nil {
			fault := *out[i].Fault
			out[i].Fault = &fault
		}
		if out[i].NextRetryAt != nil {
			at := *out[i].NextRetryAt
			out[i].NextRetryAt = &at
		}
	}
	return out
}

// Engine owns DHCP runtime and AV's existing manager observation, despite the
// latter's management owner label in the fixed table. Ignore management's DHCP
// successful rendering placeholder; it cannot override actual runtime proof.
// A local render fault remains visible even if the engine is still running.
func collect(local, engine, failures []protection.OwnerOutcome) []protection.OwnerOutcome {
	out := cloneOutcomes(engine)
	for _, o := range local {
		if o.Name != protection.SubsystemDHCP || o.Fault != nil {
			out = replace(out, o)
		}
	}
	for _, o := range failures {
		out = replace(out, o)
	}
	return out
}

func replace(out []protection.OwnerOutcome, o protection.OwnerOutcome) []protection.OwnerOutcome {
	for i := range out {
		if out[i].Name == o.Name {
			out[i] = cloneOutcomes([]protection.OwnerOutcome{o})[0]
			return out
		}
	}
	return append(out, cloneOutcomes([]protection.OwnerOutcome{o})[0])
}

// Engine-side quarantine must not turn a requested enabled operation into a
// successful disabled acknowledgement. Keep the original validation obligation.
func originalFaults(a *attempt) []protection.OwnerOutcome {
	out := cloneOutcomes(a.failures)
	for _, f := range a.prepared.Faults {
		var name protection.SubsystemName
		owner := protection.OwnerEngine
		switch f.Service {
		case config.ServiceAV:
			name, owner = protection.SubsystemAV, protection.OwnerManagement
		case config.ServiceWireGuard:
			name = protection.SubsystemWireGuard
		case config.ServiceDHCP:
			name = protection.SubsystemDHCP
		default:
			continue // management's actual owner ledger carries these faults
		}
		out = replace(out, protection.OwnerOutcome{Name: name, Owner: owner,
			DesiredRevision: a.desired(), Operation: protection.OperationApply,
			State: protection.DeliveryFailed, ObservedAt: time.Now().UTC(),
			Fault: &protection.Fault{Kind: protection.FaultConfig, Reason: "service configuration rejected"}})
	}
	return out
}

func sameAuthority(a, b config.RunningState) bool {
	if (a.Running == nil) != (b.Running == nil) || (a.Transition == nil) != (b.Transition == nil) {
		return false
	}
	if a.Running != nil {
		if a.Running.RunningRevision != b.Running.RunningRevision ||
			(a.Running.PendingConfirm == nil) != (b.Running.PendingConfirm == nil) {
			return false
		}
		if a.Running.PendingConfirm != nil && a.Running.PendingConfirm.Deadline != b.Running.PendingConfirm.Deadline {
			return false
		}
	}
	return a.Transition == nil || *a.Transition == *b.Transition
}

func (c *coordinator) Status(ctx context.Context) (protection.Aggregate, error) {
	var in protection.Input
	for range 2 {
		c.mu.Lock()
		v := c.current
		v.input.Outcomes = cloneOutcomes(v.input.Outcomes)
		c.mu.Unlock()
		in = v.input
		in.Coherent = false
		before, err := c.options.Store.ReadRunning(ctx)
		if err != nil {
			return protection.Reduce(in), err
		}
		in.DesiredRevision = ""
		if before.Running != nil {
			in.DesiredRevision = protection.Revision(before.Running.RunningRevision)
		}
		observation, err := c.options.Engine.Observe(ctx)
		if err != nil {
			return protection.Reduce(in), err
		}
		in.Engine = observation.Engine
		in.Degraded = observation.Degraded
		in.Outcomes = collect(c.options.Services.DeliveryOutcomes(), observation.Outcomes, v.input.Outcomes)
		fault, err := c.options.Store.RuntimeApplyFault(ctx)
		if err != nil {
			return protection.Reduce(in), err
		}
		after, err := c.options.Store.ReadRunning(ctx)
		if err != nil {
			return protection.Reduce(in), err
		}
		// Recheck mutable trust independently of whole-state CAS.
		if after.Running == nil {
			return protection.Reduce(in), nil
		}
		prepared, err := c.options.Environment.Prepare(ctx, after.Running)
		if err != nil {
			return protection.Reduce(in), err
		}
		_, recovery, err := c.options.Environment.Recovery(ctx, after)
		if err != nil {
			return protection.Reduce(in), err
		}
		in.Uncertain = in.Uncertain || recovery || fault != "" || after.Transition != nil ||
			after.Running.PendingConfirm != nil && !time.Now().Before(after.Running.PendingConfirm.Deadline)
		in.Coherent = v.input.Coherent && c.valid(v.epoch) &&
			sameAuthority(before, after) && in.Current.RunningRevision == in.DesiredRevision &&
			observation.BootID == in.Current.BootID &&
			prepared.Trust.Revision == string(in.DesiredTrustRevision)
		if in.Coherent {
			return protection.Reduce(in), nil
		}
	}
	return protection.Reduce(in), nil
}
