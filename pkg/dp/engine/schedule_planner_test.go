// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// scriptLog records every nft transaction applied.
type scriptLog struct {
	mu      sync.Mutex
	scripts []string
	err     error
}

func (l *scriptLog) Apply(_ context.Context, script string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	l.scripts = append(l.scripts, script)
	return nil
}

func (l *scriptLog) ReadTable(context.Context, string) (enforce.TableLayout, error) {
	return enforce.TableLayout{}, nil
}

func (l *scriptLog) take() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.scripts
	l.scripts = nil
	return out
}

// TestSchedulePlannerRefills: the planner leaves a fresh horizon alone and
// refills it once half is spent, after the clock steps back, or when forced;
// a failed refill keeps the old plan so the next check retries.
func TestSchedulePlannerRefills(t *testing.T) {
	log := &scriptLog{}
	e, err := New(Config{Enforce: EnforceConfig{ClearMark: noPolicyMarks, Enabled: true, Applier: log}})
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	e.gate.clock = func() time.Time { return t0 }
	snap := rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{{ID: "maint", Action: rules.ActionAllow,
		Protocols: []rules.Protocol{{Name: "tcp", Port: "22"}},
		Schedule:  rules.SchedulePredicate{DaysOfWeek: []string{"Saturday"}, StartTime: "02:00", EndTime: "06:00"}}}}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	if applied := log.take(); len(applied) != 1 || !strings.Contains(applied[0], "elements = { 1793412000-1793426400 }") {
		t.Fatalf("apply did not plan the horizon from its own time: %q", applied)
	}
	ctx := context.Background()
	refill := "flush set inet containd_policy schedule_allow_40_0120_0360_555443\n"
	for _, step := range []struct {
		name   string
		at     time.Time
		force  bool
		refill bool
	}{
		{"fresh horizon", t0.Add(11 * time.Hour), false, false},
		{"half spent", t0.Add(12 * time.Hour), false, true},
		{"after the refill", t0.Add(13 * time.Hour), false, false},
		{"clock stepped back", t0.Add(11 * time.Hour), false, true},
		{"clock step forced", t0.Add(11*time.Hour + time.Minute), true, true},
	} {
		if err := e.gate.planSchedules(ctx, step.at, step.force); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		applied := log.take()
		if step.refill != (len(applied) == 1) || (step.refill && !strings.HasPrefix(applied[0], refill)) {
			t.Fatalf("%s: applied %q, want refill %v", step.name, applied, step.refill)
		}
	}
	log.err = errors.New("nft unavailable")
	late := t0.Add(48 * time.Hour)
	if err := e.gate.planSchedules(ctx, late, false); err == nil {
		t.Fatal("failed refill not reported")
	}
	log.err = nil
	if err := e.gate.planSchedules(ctx, late.Add(schedulePlanInterval), false); err != nil {
		t.Fatal(err)
	}
	if applied := log.take(); len(applied) != 1 {
		t.Fatalf("the next check did not retry: %q", applied)
	}

	if err := e.ApplyRules(ctx, rules.Snapshot{Default: rules.ActionDeny}); err != nil {
		t.Fatal(err)
	}
	log.take()
	if err := e.gate.planSchedules(ctx, late.Add(48*time.Hour), true); err != nil || len(log.take()) != 0 {
		t.Fatalf("a ruleset without schedules was refilled: %v", err)
	}
}

func TestClockStepped(t *testing.T) {
	t0 := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		wall    time.Duration
		elapsed time.Duration
		stepped bool
	}{
		{30 * time.Second, 30 * time.Second, false},
		{31 * time.Second, 30 * time.Second, false},
		{time.Hour, 30 * time.Second, true},
		{-time.Hour, 30 * time.Second, true},
		{0, 30 * time.Second, true},
	} {
		if got := clockStepped(t0, t0.Add(tc.wall), tc.elapsed); got != tc.stepped {
			t.Errorf("wall %v over %v elapsed: stepped %v, want %v", tc.wall, tc.elapsed, got, tc.stepped)
		}
	}
}

// The ruleset status carries the planner's state for the installed
// ruleset: its horizon, a failing refill until the next success, and a
// degraded state once the horizon is within an hour of its end or a refill
// fails. A ruleset without scheduled rules has none.
func TestRulesetStatusReportsSchedulePlanner(t *testing.T) {
	log := &scriptLog{}
	e, err := New(Config{Enforce: EnforceConfig{ClearMark: noPolicyMarks, Enabled: true, Applier: log}})
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	now := t0
	e.gate.clock = func() time.Time { return now }
	ctx := context.Background()
	scheduled := rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{{ID: "maint", Action: rules.ActionAllow,
		Protocols: []rules.Protocol{{Name: "tcp", Port: "22"}},
		Schedule:  rules.SchedulePredicate{DaysOfWeek: []string{"Saturday"}, StartTime: "02:00", EndTime: "06:00"}}}}
	if err := e.ApplyRules(ctx, scheduled); err != nil {
		t.Fatal(err)
	}
	plan := func(state, reason string) *SchedulePlan {
		t.Helper()
		p := e.RulesetStatus().SchedulePlanner
		if p == nil || p.State != state || p.Reason != reason {
			t.Fatalf("planner at %v = %+v, want %s %q", now, p, state, reason)
		}
		return p
	}
	if p := plan(SchedulePlannerOK, ""); !p.LastRefill.Equal(t0) || !p.HorizonEnd.Equal(t0.Add(enforce.DefaultScheduleHorizon)) || p.LastError != "" {
		t.Fatalf("planner after apply = %+v", p)
	}
	now = t0.Add(23*time.Hour + 30*time.Minute)
	plan(SchedulePlannerDegraded, "schedule horizon ends within an hour")
	now = t0.Add(25 * time.Hour)
	plan(SchedulePlannerDegraded, "schedule horizon exhausted")

	log.err = errors.New("nft unavailable")
	if err := e.gate.planSchedules(ctx, now, false); err == nil {
		t.Fatal("failed refill not reported")
	}
	if p := plan(SchedulePlannerDegraded, "schedule refill failing"); p.LastError != "nft unavailable" || p.LastErrorAt == nil || !p.LastRefill.Equal(t0) {
		t.Fatalf("planner after a failed refill = %+v", p)
	}
	log.err = nil
	if err := e.gate.planSchedules(ctx, now, false); err != nil {
		t.Fatal(err)
	}
	if p := plan(SchedulePlannerOK, ""); !p.LastRefill.Equal(now) || p.LastError != "" || p.LastErrorAt != nil {
		t.Fatalf("planner after the refill = %+v", p)
	}

	// A failed apply leaves the installed plan.
	log.err = errors.New("nft unavailable")
	if err := e.ApplyRules(ctx, rules.Snapshot{Default: rules.ActionDeny}); err == nil {
		t.Fatal("apply error swallowed")
	}
	plan(SchedulePlannerOK, "")
	log.err = nil
	if err := e.ApplyRules(ctx, rules.Snapshot{Default: rules.ActionDeny}); err != nil {
		t.Fatal(err)
	}
	if p := e.RulesetStatus().SchedulePlanner; p != nil {
		t.Fatalf("planner of a ruleset without schedules = %+v", p)
	}
}
