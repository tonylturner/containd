// SPDX-License-Identifier: Apache-2.0

package convergence

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type attempt struct {
	admission protection.Admission
	snapshot  *config.RunningSnapshot
	prepared  Prepared
	effective *config.Config
	rules     rules.Snapshot
	failures  []protection.OwnerOutcome
	enforcing bool
	uncertain bool
	baseline  bool
	completed bool
	epoch     uint64
	renew     bool
	addresses []config.Interface
	warnings  []string
	replace   protection.SubsystemName
	phases    map[protection.SubsystemName]bool
}

func (a *attempt) desired() protection.Revision {
	if a.snapshot == nil {
		return ""
	}
	return protection.Revision(a.snapshot.RunningRevision)
}

func (c *coordinator) cycle(ctx context.Context, epoch uint64, force bool, previous *config.RunningSnapshot) error {
	state, err := c.options.Store.ReadRunning(ctx)
	if err != nil {
		return err
	}
	// No owner effects are allowed while this authoritative pending generation
	// has expired. The store timer may have already won; a CAS loss is coalesced.
	if state.Running != nil && state.Running.PendingConfirm != nil &&
		!time.Now().Before(state.Running.PendingConfirm.Deadline) {
		// This worker has not performed effects. Retire its publication lease,
		// but preserve its bounded context for the rollback transaction itself.
		c.mu.Lock()
		c.retireLocked()
		c.mu.Unlock()
		_, err := c.options.Store.Rollback(ctx, state.Revision)
		c.signal()
		return err
	}
	plan, recovery, err := c.options.Environment.Recovery(ctx, state)
	if err != nil {
		return err
	}
	blocked := state.Transition != nil && state.Transition.State != config.TransitionReapplyPending
	if blocked {
		recovery = true
	}
	if recovery {
		c.resetDemo(ctx)
		return c.recover(ctx, epoch, state, plan, blocked)
	}
	if state.Running == nil {
		c.invalidate()
		c.resetDemo(ctx)
		return nil
	}
	err = c.deliver(ctx, epoch, state.Running, force, previous, "")
	if err != nil {
		if c.valid(epoch) && ctx.Err() == nil {
			err = errors.Join(err, c.options.Store.SetRuntimeApplyFault(ctx, state.Running.RunningRevision, "runtime delivery pending"))
		}
		return err
	}
	after, err := c.options.Store.ReadRunning(ctx)
	if err != nil {
		return err
	}
	if !sameAuthority(state, after) || !c.valid(epoch) {
		return ErrSuperseded
	}
	id := ""
	if state.Transition != nil {
		id = state.Transition.ID
	}
	fault, err := c.options.Store.RuntimeApplyFault(ctx)
	if err != nil {
		return err
	}
	if state.Transition != nil || fault != "" || !c.work.completed {
		if err := c.options.Store.CompleteRuntimeApply(ctx, state.Running.RunningRevision, id); err != nil {
			return err
		}
		c.work.completed = true
	}
	return nil
}

func (c *coordinator) newAttempt(ctx context.Context, epoch uint64, snapshot *config.RunningSnapshot, p Prepared, observed Observation) (*attempt, error) {
	id, err := mintApplyID()
	if err != nil {
		return nil, err
	}
	m := protection.Metadata{BootID: observed.BootID, ApplyID: id,
		RunningRevision: protection.Revision(snapshot.RunningRevision), Mode: protection.ModeNormal}
	if !m.Valid() {
		return nil, errors.New("invalid running or engine boot identity")
	}
	a := &attempt{snapshot: snapshot, prepared: p, effective: p.Effective, enforcing: snapshot.DataPlane.Enforcement,
		admission: protection.Admission{Metadata: m, PreviousApplyID: observed.Engine.ApplyID},
		epoch:     epoch, phases: map[protection.SubsystemName]bool{}}
	c.work = a
	c.publish(epoch, a)
	c.resetDemo(ctx)
	return a, nil
}

func (c *coordinator) deliver(ctx context.Context, epoch uint64, next *config.RunningSnapshot, force bool, previous *config.RunningSnapshot, replace protection.SubsystemName) error {
	if !c.valid(epoch) {
		return ErrSuperseded
	}
	p, err := c.prepare(ctx, next)
	if err != nil {
		return err
	}
	observed, err := c.options.Engine.Observe(ctx)
	if err != nil {
		return err
	}
	a := c.work
	fresh := force || a == nil || a.renew || a.epoch != epoch ||
		a.admission.Mode != protection.ModeNormal || a.admission.BootID != observed.BootID ||
		a.snapshot.RunningRevision != next.RunningRevision || !reflect.DeepEqual(a.prepared, p)
	if fresh {
		a, err = c.newAttempt(ctx, epoch, next, p, observed)
		if err != nil {
			return err
		}
	} else {
		a.snapshot = next // confirm changes deadline without replaying owners
	}
	var effective config.ServicesConfig
	if fresh {
		local, err := c.options.Services.ApplyDelivery(ctx, a.admission.Metadata, next.Services, p.Faults)
		if err != nil {
			return err
		}
		effective = local.Effective
	} else {
		local, err := c.options.Services.RetryDelivery(ctx, a.admission.Metadata)
		if err != nil {
			return err
		}
		effective = local.Effective
	}
	projection := *p.Effective
	projection.Services = effective
	snapshot, err := compile.CompileSnapshot(&projection)
	if err != nil {
		return err
	}
	// A recovered local service can change local INPUT or resolved VPN policy.
	// Never send that recovered policy under an already admitted narrowed ID.
	if !fresh && (!reflect.DeepEqual(a.effective, &projection) || !reflect.DeepEqual(a.rules, snapshot)) {
		a, err = c.newAttempt(ctx, epoch, next, p, observed)
		if err != nil {
			return err
		}
		local, err := c.options.Services.ApplyDelivery(ctx, a.admission.Metadata, next.Services, p.Faults)
		if err != nil {
			return err
		}
		// Adoption itself can discover loss. Compile the result the owner
		// actually returned, not the optimistic projection preceding adoption.
		projection.Services = local.Effective
		snapshot, err = compile.CompileSnapshot(&projection)
		if err != nil {
			return err
		}
		fresh = true
	}
	a.effective, a.rules, a.replace = &projection, snapshot, replace
	a.baseline = a.baseline && !fresh
	// Outcomes are observations, not transport success. Missing acknowledgements
	// keep an owner outstanding even after an HTTP 200 response.
	if observed.Engine.Metadata == a.admission.Metadata {
		c.revokeMissing(a, observed)
	}
	if !a.phases[protection.SubsystemConfig] || !a.phases[protection.SubsystemNFT] {
		a.baseline = false
		c.resetDemo(ctx)
	}
	c.publish(epoch, a)
	if err := c.deliverEngine(ctx, epoch, a, fresh); err != nil {
		c.publish(epoch, a)
		return err
	}
	if c.pcapBoot != a.admission.BootID || c.pcapSnapshot == nil ||
		c.pcapSnapshot.RunningRevision != next.RunningRevision {
		if c.pcapBoot != a.admission.BootID {
			previous = nil
		} else if previous == nil {
			previous = c.pcapSnapshot
		}
		a.warnings = c.options.Environment.SavedPCAP(ctx, previous, next)
		// One shot, including failure. Trust changes, recovered projections and
		// auxiliary retries never reapply saved PCAP over operational captures.
		c.pcapBoot, c.pcapSnapshot = a.admission.BootID, next
	}
	if !c.publish(epoch, a) {
		return ErrSuperseded
	}
	c.demo(ctx, epoch, a)
	return nil
}

// prepare rejects invalid policy before any effect, including explicit
// referenced-material reload. Reload is followed by another preparation because
// it can change the resolved runtime inputs.
func (c *coordinator) prepare(ctx context.Context, next *config.RunningSnapshot) (Prepared, error) {
	p, err := c.options.Environment.Prepare(ctx, next)
	if err != nil {
		return p, err
	}
	if p.Effective == nil {
		return p, errors.New("missing effective projection")
	}
	if err := p.Trust.Validate(); err != nil {
		return p, err
	}
	_, err = compile.CompileSnapshot(p.Effective)
	return p, err
}

// Fixed dependencies: interfaces precede routing and DHCP; trust precedes engine
// TLS services. Config and nft form the critical baseline. No generic workflow
// graph or independent runtime supervisors live here.
func (c *coordinator) deliverEngine(ctx context.Context, epoch uint64, a *attempt, fresh bool) error {
	run := func(name protection.SubsystemName, critical bool, fn func() error) error {
		if !c.valid(epoch) {
			return ErrSuperseded
		}
		if a.phases[name] {
			return nil
		}
		// Revoke the visible prior proof before invoking the mutating owner.
		a.failure(name, nil)
		c.publish(epoch, a)
		err := fn()
		a.phases[name] = err == nil
		if err != nil {
			if errors.Is(err, ErrInputChanged) {
				a.renew = true
				return err
			}
			a.failure(name, err)
			if critical {
				return fmt.Errorf("%s: %w", name, err)
			}
		} else {
			a.clearFailure(name)
		}
		return nil
	}
	m := a.admission
	cfg := a.effective
	if err := run(protection.SubsystemInterfaces, false, func() error {
		return c.options.Engine.ConfigureInterfaces(ctx, m, cfg.Interfaces, a.replace == protection.SubsystemInterfaces)
	}); err != nil {
		return err
	}
	if a.phases[protection.SubsystemInterfaces] {
		if err := run(protection.SubsystemRouting, false, func() error {
			return c.options.Engine.ConfigureRouting(ctx, m, cfg.Routing, a.replace == protection.SubsystemRouting)
		}); err != nil {
			return err
		}
	}
	if err := run(protection.SubsystemTrust, false, func() error {
		return c.options.Engine.ConfigureTrust(ctx, m, a.prepared.Trust)
	}); err != nil {
		return err
	}
	// Engine services receive the validated pre-local-quarantine AV/WG/DHCP
	// inputs, not management's narrower traffic-service projection.
	if a.phases[protection.SubsystemInterfaces] && a.phases[protection.SubsystemTrust] {
		if err := run(protection.SubsystemAV, false, func() error {
			return c.options.Engine.ConfigureServices(ctx, m, a.prepared.Effective.Services)
		}); err != nil {
			return err
		}
	}
	if err := run(protection.SubsystemConfig, true, func() error {
		return c.options.Engine.Configure(ctx, m, cfg.DataPlane)
	}); err != nil {
		return err
	}
	if err := run(protection.SubsystemNFT, true, func() error {
		return c.options.Engine.ApplyRules(ctx, m, a.rules)
	}); err != nil {
		return err
	}
	a.baseline = true
	if !fresh {
		o, err := c.options.Engine.Observe(ctx)
		if err != nil {
			return err
		}
		if retryEngine(o, a.admission.Metadata) {
			if err := c.options.Engine.Retry(ctx, m); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func retryEngine(o Observation, m protection.Metadata) bool {
	if o.Engine.Metadata != m {
		return false
	}
	if o.Retryable {
		return true
	}
	for _, out := range o.Outcomes {
		if out.Retryable && (out.Acknowledged == nil || out.Fault != nil) {
			return true
		}
	}
	return false
}

func (c *coordinator) revokeMissing(a *attempt, o Observation) {
	names := []protection.SubsystemName{protection.SubsystemInterfaces, protection.SubsystemRouting,
		protection.SubsystemTrust, protection.SubsystemConfig}
	if a.enforcing {
		names = append(names, protection.SubsystemNFT)
	}
	for _, name := range names {
		found := false
		for _, out := range o.Outcomes {
			found = found || out.Name == name && out.Acknowledged != nil &&
				out.Acknowledged.Metadata == a.admission.Metadata && out.Fault == nil
		}
		a.phases[name] = a.phases[name] && found
	}
	// Missing service telemetry is not a terminal owner decision. Redeliver the
	// identical phase so each owner can positively adopt or repair itself.
	for _, name := range []protection.SubsystemName{protection.SubsystemAV, protection.SubsystemWireGuard, protection.SubsystemDHCP} {
		found := false
		for _, out := range o.Outcomes {
			found = found || out.Name == name && out.DesiredRevision == a.desired()
		}
		if !found {
			a.phases[protection.SubsystemAV] = false
		}
	}
}

func (a *attempt) failure(name protection.SubsystemName, err error) {
	out := protection.OwnerOutcome{Name: name, Owner: protection.OwnerEngine, DesiredRevision: a.desired(),
		Operation: protection.OperationApply, State: protection.DeliveryPending, ObservedAt: time.Now().UTC()}
	if name == protection.SubsystemAV {
		out.Owner = protection.OwnerManagement
	}
	if err != nil {
		out.State, out.Retryable = protection.DeliveryFailed, true
		out.Reason = "owner delivery failed"
		out.Fault = &protection.Fault{Kind: protection.FaultDelivery, Reason: out.Reason}
	}
	a.failures = replace(a.failures, out)
}

func (a *attempt) clearFailure(name protection.SubsystemName) {
	for i, out := range a.failures {
		if out.Name == name {
			a.failures = append(a.failures[:i], a.failures[i+1:]...)
			return
		}
	}
}

func (c *coordinator) resetDemo(ctx context.Context) {
	c.hooks.Lock()
	defer c.hooks.Unlock()
	c.demoKey = protection.Metadata{}
	if c.options.Demo != nil {
		c.options.Demo.Reset(ctx)
	}
}

func (c *coordinator) demo(ctx context.Context, epoch uint64, a *attempt) {
	c.hooks.Lock()
	defer c.hooks.Unlock()
	if c.options.Demo == nil || !c.valid(epoch) || !a.baseline || a.admission.Mode != protection.ModeNormal {
		return
	}
	if c.demoKey != a.admission.Metadata {
		c.options.Demo.EngineSynced(ctx, string(a.admission.BootID))
		c.demoKey = a.admission.Metadata
	}
	c.options.Demo.Reconcile(ctx)
}
