// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"
	"time"
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
	script, err := g.comp.ScheduleRefresh(g.snap)
	if err != nil {
		return err
	}
	if script != "" {
		ctx, cancel := context.WithTimeout(ctx, envelopeSwitchTimeout)
		defer cancel()
		if err := g.applier.Apply(ctx, script); err != nil {
			return err
		}
	}
	g.planned = now
	return nil
}
