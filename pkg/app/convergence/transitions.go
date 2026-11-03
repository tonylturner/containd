// SPDX-License-Identifier: Apache-2.0

package convergence

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// transition cancels/joins before entering RuntimeStore. In particular neither
// callback reads the store, joins another worker, nor depends on caller lifetime
// for the store's independently bounded compensating reapply.
func (c *coordinator) transition(ctx context.Context, change func(context.Context, func(context.Context, *config.RunningSnapshot, *config.RunningSnapshot) error) (config.Revision, error)) (Result, error) {
	if err := c.enter(ctx); err != nil {
		return Result{}, err
	}
	defer c.leave()
	if err := c.drain(ctx); err != nil {
		return Result{}, err
	}
	c.invalidate()
	c.resetDemo(ctx)
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, ApplyBudget)
	defer cancel()
	result := Result{}
	revision, err := change(ctx, func(effectCtx context.Context, previous, next *config.RunningSnapshot) error {
		if next == nil {
			return errors.New("missing labelled running target")
		}
		// A compensation callback carries a fresh restored revision; the same
		// delivery path therefore discards rejected-target work automatically.
		if err := c.deliver(effectCtx, c.epoch(), next, true, previous, ""); err != nil {
			return err
		}
		result = c.result()
		return nil
	})
	result.Revision = revision
	// Reload AFTER RuntimeStore returns, including restoration/conflict outcomes.
	// No old completion/fault is ever attached to newer store authority.
	remaining := func() time.Duration { return max(0, 2*ApplyBudget-time.Since(started)) }
	readCtx, readCancel := context.WithTimeout(context.WithoutCancel(ctx), min(RetryBudget, remaining()))
	defer readCancel()
	state, readErr := c.options.Store.ReadRunning(readCtx)
	if readErr == nil && state.Running != nil {
		result.RunningRevision = state.Running.RunningRevision
	}
	if err != nil || readErr != nil {
		c.invalidate()
		c.resetDemo(context.WithoutCancel(ctx))
		var failure *config.ApplyError
		if errors.As(err, &failure) && failure.Recovery && readErr == nil {
			// The refused previous document is not a normal replay target.
			// Reenter fail-closed recovery synchronously, without extending the
			// total forward + compensation exception by another 30 seconds.
			recoveryCtx, recoveryCancel := context.WithTimeout(context.WithoutCancel(ctx), remaining())
			plan, _, recoveryErr := c.options.Environment.Recovery(recoveryCtx, state)
			if recoveryErr == nil {
				recoveryErr = c.recover(recoveryCtx, c.epoch(), state, plan, true)
			}
			failure.ReapplyError = recoveryErr
			result.ApplyID = c.result().ApplyID
			recoveryCancel()
		}
		c.signal()
	}
	return result, errors.Join(err, readErr)
}

func (c *coordinator) Change(ctx context.Context, expected config.Revision, kind config.RunningChange, ttl time.Duration) (Result, error) {
	return c.transition(ctx, func(ctx context.Context, apply func(context.Context, *config.RunningSnapshot, *config.RunningSnapshot) error) (config.Revision, error) {
		return c.options.Store.ApplyChange(ctx, expected, kind, ttl, apply)
	})
}

func (c *coordinator) Reset(ctx context.Context, expected config.Revision, defaults *config.Config) (Result, error) {
	return c.transition(ctx, func(ctx context.Context, apply func(context.Context, *config.RunningSnapshot, *config.RunningSnapshot) error) (config.Revision, error) {
		return c.options.Store.ApplyReset(ctx, expected, defaults, apply)
	})
}

func (c *coordinator) Confirm(ctx context.Context, expected config.Revision) (config.Revision, error) {
	if err := c.enter(ctx); err != nil {
		return "", err
	}
	defer c.leave()
	if err := c.drain(ctx); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, RetryBudget)
	defer cancel()
	revision, err := c.options.Store.ConfirmCommit(ctx, expected)
	if err != nil {
		return "", err
	}
	state, err := c.options.Store.ReadRunning(ctx)
	if err != nil {
		return revision, err
	}
	c.mu.Lock()
	if state.Running != nil && state.Running.PendingConfirm == nil &&
		protection.Revision(state.Running.RunningRevision) == c.current.input.Current.RunningRevision {
		c.current.deadline = time.Time{}
	}
	c.mu.Unlock()
	c.signal()
	return revision, nil
}

func (c *coordinator) result() Result {
	r := Result{}
	if a := c.work; a != nil {
		r.ApplyID = a.admission.ApplyID
		r.RunningRevision = config.RunningRevision(a.desired())
		r.Warnings = append([]string(nil), a.warnings...)
	}
	return r
}

func (c *coordinator) Replay(ctx context.Context, refresh bool) (Result, error) {
	return c.exclusive(ctx, func(ctx context.Context) error {
		if refresh {
			state, err := c.options.Store.ReadRunning(ctx)
			if err != nil {
				return err
			}
			if state.Running == nil {
				return errors.New("no running configuration")
			}
			if state.Transition != nil && state.Transition.State != config.TransitionReapplyPending {
				return ErrUncertain
			}
			if _, err := c.prepare(ctx, state.Running); err != nil {
				return err
			}
			if err := c.options.Environment.Refresh(ctx, state.Running); err != nil {
				return err
			}
		}
		return c.cycle(ctx, c.epoch(), true, nil)
	})
}

// TrustChanged fences the durable material write with delivery. A write success
// and delivery failure are distinct: the material stays stored and Run retries.
func (c *coordinator) TrustChanged(ctx context.Context, write func(context.Context, *config.RunningSnapshot) error) (Result, error) {
	if write == nil {
		return Result{}, errors.New("trust write callback is nil")
	}
	return c.exclusive(ctx, func(ctx context.Context) error {
		state, err := c.options.Store.ReadRunning(ctx)
		if err != nil {
			return err
		}
		if state.Running == nil {
			return errors.New("no running configuration")
		}
		if err := write(ctx, state.Running); err != nil {
			return err
		}
		return c.cycle(ctx, c.epoch(), true, nil)
	})
}

func (c *coordinator) exclusive(ctx context.Context, effect func(context.Context) error) (Result, error) {
	if err := c.enter(ctx); err != nil {
		return Result{}, err
	}
	defer c.leave()
	if err := c.drain(ctx); err != nil {
		return Result{}, err
	}
	c.invalidate()
	c.resetDemo(ctx)
	ctx, cancel := context.WithTimeout(ctx, ApplyBudget)
	defer cancel()
	err := effect(ctx)
	r := c.result()
	c.signal()
	return r, err
}

// Reconcile is the only destructive replace entry. Authorization, confirmation
// and reservation checks belong in the caller; automatic retries always merge.
func (c *coordinator) Reconcile(ctx context.Context, name protection.SubsystemName) error {
	if name != protection.SubsystemInterfaces && name != protection.SubsystemRouting {
		return errors.New("only interfaces and routing support explicit replace")
	}
	_, err := c.exclusive(ctx, func(ctx context.Context) error {
		state, err := c.options.Store.ReadRunning(ctx)
		if err != nil {
			return err
		}
		if state.Running == nil || state.Transition != nil {
			return ErrUncertain
		}
		if state.Running.PendingConfirm != nil && !time.Now().Before(state.Running.PendingConfirm.Deadline) {
			return ErrSuperseded
		}
		_, recovery, err := c.options.Environment.Recovery(ctx, state)
		if err != nil {
			return err
		}
		if recovery {
			return ErrUncertain
		}
		// Replace is a distinct immutable phase input and needs its own attempt.
		// Its successor returns to normal non-destructive reconciliation, even
		// when the explicit replace fails partway through.
		defer c.invalidate()
		return c.deliver(ctx, c.epoch(), state.Running, true, state.Running, name)
	})
	return err
}

func (c *coordinator) recover(ctx context.Context, epoch uint64, state config.RunningState, plan RecoveryPlan, uncertain bool) error {
	if plan.Rules.Version != config.ManagementRecoveryVersion {
		return errors.New("missing validated management recovery plan")
	}
	observed, err := c.options.Engine.Observe(ctx)
	if err != nil {
		return err
	}
	a := c.work
	fresh := a == nil || a.epoch != epoch || a.admission.BootID != observed.BootID ||
		a.admission.Mode != protection.ModeRecovery || !reflect.DeepEqual(a.rules, plan.Rules) ||
		!reflect.DeepEqual(a.addresses, plan.Addresses)
	if fresh {
		c.resetDemo(ctx)
		id, err := mintApplyID()
		if err != nil {
			return err
		}
		m := protection.Metadata{BootID: observed.BootID, ApplyID: id, Mode: protection.ModeRecovery,
			RunningRevision: protection.RecoveryRevision(observed.BootID)}
		if !m.Valid() {
			return errors.New("invalid recovery boot")
		}
		a = &attempt{admission: protection.Admission{Metadata: m, PreviousApplyID: observed.Engine.ApplyID},
			snapshot: state.Running, epoch: epoch, uncertain: uncertain, enforcing: true,
			rules: plan.Rules, addresses: plan.Addresses,
			phases: map[protection.SubsystemName]bool{}}
		c.work = a
	}
	c.publish(epoch, a)
	if !a.phases[protection.SubsystemConfig] {
		if err := c.options.Engine.Configure(ctx, a.admission, config.DataPlaneConfig{Enforcement: true}); err != nil {
			return err
		}
		a.phases[protection.SubsystemConfig] = true
	}
	if !a.phases[protection.SubsystemNFT] {
		if err := c.options.Engine.ApplyRules(ctx, a.admission, plan.Rules); err != nil {
			return err
		}
		a.phases[protection.SubsystemNFT] = true
	}
	if len(plan.Addresses) > 0 && !a.phases[protection.SubsystemInterfaces] {
		err := c.options.Engine.ConfigureInterfaces(ctx, a.admission, plan.Addresses, false)
		a.phases[protection.SubsystemInterfaces] = err == nil
		if err != nil {
			a.failure(protection.SubsystemInterfaces, err)
		} else {
			a.clearFailure(protection.SubsystemInterfaces)
		}
	}
	c.publish(epoch, a)
	return ctx.Err()
}
