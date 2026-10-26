// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// The schedule planner keeps the kernel's schedule time sets filled ahead
// of their horizon (see pkg/dp/enforce/schedule.go). Every apply plans a
// full horizon from its own time; the planner refills it once half of it
// has passed, and at once after the wall clock steps. The kernel opens and
// closes windows itself, so a paused or dead planner changes nothing until
// the horizon runs out, and then a scheduled ALLOW stops matching and a
// scheduled DENY applies.

const (
	// schedulePlanInterval is how often the planner checks the horizon
	// and the clock.
	schedulePlanInterval = 30 * time.Second
	// scheduleClockStep is how far the wall clock may move apart from
	// the monotonic clock between two checks before it counts as a step.
	scheduleClockStep = 2 * time.Second
)

// runSchedulePlanner checks the installed time sets every
// schedulePlanInterval until ctx ends. A failed refill is reported and
// retried at the next check.
func (e *Engine) runSchedulePlanner(ctx context.Context, onError func(error)) {
	ticker := time.NewTicker(schedulePlanInterval)
	defer ticker.Stop()
	last := time.Now()
	for {
		now := time.Now()
		stepped := clockStepped(last.Round(0), now.Round(0), now.Sub(last))
		last = now
		if err := e.gate.planSchedules(ctx, now.Round(0), stepped); err != nil && onError != nil {
			onError(fmt.Errorf("schedule planner: %w", err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// clockStepped reports whether the wall clock moved from prevWall to
// nowWall differently from the monotonic elapsed time between the readings.
func clockStepped(prevWall, nowWall time.Time, elapsed time.Duration) bool {
	drift := nowWall.Sub(prevWall) - elapsed
	return drift > scheduleClockStep || drift < -scheduleClockStep
}

// planSchedules refills the installed ruleset's time sets with a horizon
// starting at now when the planned horizon is half spent, starts after now
// (the clock stepped back), or force is set.
func (g *envelopeGate) planSchedules(ctx context.Context, now time.Time, force bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.comp == nil || g.snap == nil {
		return nil
	}
	half := g.comp.ScheduleHorizonLength() / 2
	if !force && !now.Before(g.planned) && now.Before(g.planned.Add(half)) {
		return nil
	}
	g.comp.ScheduleFrom = now
	if err := g.refillLocked(ctx); err != nil {
		g.recordRefillFailure(now, err)
		return err
	}
	g.planned = now
	g.plan.Store(newSchedulePlan(g.snap, g.comp))
	return nil
}

// refillLocked writes the installed ruleset's time sets for the horizon
// starting at g.comp.ScheduleFrom.
func (g *envelopeGate) refillLocked(ctx context.Context) error {
	script, err := g.comp.ScheduleRefresh(g.snap)
	if err != nil || script == "" {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, envelopeSwitchTimeout)
	defer cancel()
	return g.applier.Apply(ctx, script)
}

// Planner health: a failing refill, or a horizon that ends within
// scheduleHorizonMargin, is degraded. A healthy planner refills when half
// the horizon is left, so neither happens while it works.
const (
	scheduleHorizonMargin = time.Hour

	SchedulePlannerOK       = "ok"
	SchedulePlannerDegraded = "degraded"
)

// SchedulePlan is the schedule planner's state for the installed ruleset:
// the horizon its time sets hold and the last refill failure, which the
// next successful refill clears. State and Reason are evaluated when the
// status is read.
type SchedulePlan struct {
	LastRefill  time.Time  `json:"lastRefill"`
	HorizonEnd  time.Time  `json:"horizonEnd"`
	LastError   string     `json:"lastError,omitempty"`
	LastErrorAt *time.Time `json:"lastErrorAt,omitempty"`
	State       string     `json:"state"`
	Reason      string     `json:"reason,omitempty"`
}

// newSchedulePlan is the plan of a ruleset just installed or refilled for
// snap by comp, or nil when snap has no scheduled rule.
func newSchedulePlan(snap *rules.Snapshot, comp *enforce.Compiler) *SchedulePlan {
	if !slices.ContainsFunc(snap.Firewall, rules.Entry.HasSchedulePredicate) {
		return nil
	}
	from := comp.ScheduleFrom.Truncate(time.Second).UTC()
	return &SchedulePlan{LastRefill: from, HorizonEnd: from.Add(comp.ScheduleHorizonLength())}
}

// recordRefillFailure adds a failed refill at now to the plan, which keeps
// the horizon the time sets still hold.
func (g *envelopeGate) recordRefillFailure(now time.Time, err error) {
	prev := g.plan.Load()
	if prev == nil {
		return
	}
	plan := *prev
	at := now.UTC()
	plan.LastError, plan.LastErrorAt = err.Error(), &at
	g.plan.Store(&plan)
}

// schedulePlanAt returns the installed ruleset's plan with its state at
// now, or nil when it has no scheduled rule.
func (g *envelopeGate) schedulePlanAt(now time.Time) *SchedulePlan {
	prev := g.plan.Load()
	if prev == nil {
		return nil
	}
	plan := *prev
	switch {
	case plan.LastError != "":
		plan.State, plan.Reason = SchedulePlannerDegraded, "schedule refill failing"
	case !now.Before(plan.HorizonEnd):
		plan.State, plan.Reason = SchedulePlannerDegraded, "schedule horizon exhausted"
	case !now.Before(plan.HorizonEnd.Add(-scheduleHorizonMargin)):
		plan.State, plan.Reason = SchedulePlannerDegraded, "schedule horizon ends within an hour"
	default:
		plan.State = SchedulePlannerOK
	}
	return &plan
}
