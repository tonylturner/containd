// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type accountingApplier struct {
	recordingApplier
	values map[string]enforce.CounterValue
	read   func()
}

func (a *accountingApplier) ReadAccountingCounters(context.Context, string) (map[string]enforce.CounterValue, error) {
	if a.read != nil {
		a.read()
	}
	return a.values, nil
}

func telemetryEngine(t *testing.T, a enforce.Applier, enabled bool, table string, store *events.Store) *Engine {
	t.Helper()
	e, err := New(Config{Events: store, Enforce: EnforceConfig{Enabled: enabled, TableName: table, Applier: a, ClearMark: noPolicyMarks}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

func TestTelemetryAccountingLifetime(t *testing.T) {
	ctx := context.Background()
	a := &accountingApplier{values: map[string]enforce.CounterValue{}}
	e := telemetryEngine(t, a, true, "fw", nil)
	if _, missing := e.TelemetryConduits(ctx); len(missing) != 1 || missing[0].Reason != "interfaces not applied" {
		t.Fatal(missing)
	}
	ifaces := []config.Interface{{Name: "eth0", Zone: "a"}, {Name: "eth1", Zone: "b"}}
	if err := e.SetTelemetryInterfaces(ctx, ifaces); err != nil {
		t.Fatal(err)
	}
	apply := func() {
		t.Helper()
		if err := e.ApplyRules(ctx, rules.Snapshot{Default: rules.ActionAllow}); err != nil {
			t.Fatal(err)
		}
	}
	apply()
	first := e.gate.accountingStatus.Load().build
	if !strings.Contains(a.ruleset, "table inet fw_acct") {
		t.Fatal("first ruleset omitted accounting")
	}
	for _, p := range first.Pairs {
		a.values[p.Counter] = enforce.CounterValue{Packets: 7, Bytes: 70}
	}
	samples, missing := e.TelemetryConduits(ctx)
	if len(samples) != 4 || len(missing) != 0 {
		t.Fatalf("%+v %+v", samples, missing)
	}
	apply()
	if strings.Contains(a.ruleset, "_acct") || e.gate.accountingStatus.Load().build.Epoch != first.Epoch {
		t.Fatal("policy apply rebuilt accounting")
	}
	samples, _ = e.TelemetryConduits(ctx)
	if samples[0].Value != 70 {
		t.Fatal(samples)
	}
	ifaces[0].Alias = "renamed display"
	if err := e.SetTelemetryInterfaces(ctx, ifaces); err != nil {
		t.Fatal(err)
	}
	if e.gate.accountingStatus.Load().build != first {
		t.Fatal("non-membership change rebuilt table")
	}
	ifaces[0].Zone = "c"
	if err := e.SetTelemetryInterfaces(ctx, ifaces); err != nil {
		t.Fatal(err)
	}
	if e.gate.accountingStatus.Load().build.Epoch == first.Epoch {
		t.Fatal("membership change reused epoch")
	}
	prevGeneration := e.TelemetryTracker().Generation()
	fresh := telemetryEngine(t, a, false, "", e.Events())
	if err := e.Reconfigure(fresh); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.ruleset, "delete table inet fw_acct") {
		t.Fatal("disable kept accounting table")
	}
	if _, missing := e.TelemetryConduits(ctx); len(missing) != 1 || missing[0].Reason != "enforcement disabled" {
		t.Fatal(missing)
	}
	if e.TelemetryTracker().Generation() == prevGeneration || len(e.TelemetryMembership().Interfaces) != 2 {
		t.Fatal("reconfigure lost membership or kept tracker epoch")
	}
	fresh = telemetryEngine(t, a, true, "fw", e.Events())
	if err := e.Reconfigure(fresh); err != nil {
		t.Fatal(err)
	}
	apply()
	enabled := e.gate.accountingStatus.Load().build
	if enabled.Epoch == first.Epoch {
		t.Fatal("reenable reused epoch")
	}
	fresh = telemetryEngine(t, a, true, "renamed", e.Events())
	if err := e.Reconfigure(fresh); err != nil {
		t.Fatal(err)
	}
	apply()
	renamed := e.gate.accountingStatus.Load().build
	if renamed.Epoch == enabled.Epoch || renamed.Table != "renamed_acct" || !strings.Contains(a.ruleset, "delete table inet fw_acct") {
		t.Fatal("rename failed accounting retirement/build")
	}
}

func TestTelemetryMissingCounterAndFailedBuild(t *testing.T) {
	ctx := context.Background()
	a := &accountingApplier{}
	e := telemetryEngine(t, a, true, "fw", nil)
	ifaces := []config.Interface{{Name: "eth0", Zone: "a"}, {Name: "eth1", Zone: "other"}}
	if err := e.SetTelemetryInterfaces(ctx, ifaces); err != nil {
		t.Fatal(err)
	}
	if err := e.ApplyRules(ctx, rules.Snapshot{Default: rules.ActionAllow}); err != nil {
		t.Fatal(err)
	}
	samples, missing := e.TelemetryConduits(ctx)
	if len(samples) != 0 || len(missing) != 4 || missing[0].Metric == "" {
		t.Fatalf("%+v %+v", samples, missing)
	}
	before := e.gate.accountingStatus.Load()
	a.err = errors.New("nft failed")
	if err := e.ApplyRules(ctx, rules.Snapshot{Default: rules.ActionDeny}); err == nil {
		t.Fatal("apply succeeded")
	}
	if e.gate.accountingStatus.Load() != before {
		t.Fatal("failed policy changed accounting")
	}
	ifaces[0].Zone = "b"
	if err := e.SetTelemetryInterfaces(ctx, ifaces); err == nil {
		t.Fatal("build succeeded")
	}
	if _, missing := e.TelemetryConduits(ctx); len(missing) != 1 || missing[0].Reason != "nft failed" {
		t.Fatal(missing)
	}
	if e.TelemetryMembership().Interfaces[0].Zone != "b" {
		t.Fatal("successful interface apply lost on telemetry error")
	}
	a.err = nil
	if err := e.ApplyRules(ctx, rules.Snapshot{Default: rules.ActionAllow}); err != nil {
		t.Fatal(err)
	}
	if e.gate.accountingStatus.Load().build == nil {
		t.Fatal("apply did not recover failed build")
	}
}

func TestTelemetryReadDuringRebuild(t *testing.T) {
	ctx := context.Background()
	entered, release := make(chan struct{}), make(chan struct{})
	releaseRead := sync.OnceFunc(func() { close(release) })
	defer releaseRead()
	a := &accountingApplier{read: func() { close(entered); <-release }}
	e := telemetryEngine(t, a, true, "fw", nil)
	ifaces := []config.Interface{{Name: "eth0", Zone: "a"}, {Name: "eth1", Zone: "other"}}
	if err := e.SetTelemetryInterfaces(ctx, ifaces); err != nil {
		t.Fatal(err)
	}
	if err := e.ApplyRules(ctx, rules.Snapshot{Default: rules.ActionAllow}); err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() {
		_, missing := e.TelemetryConduits(ctx)
		if len(missing) == 1 {
			done <- missing[0].Reason
		} else {
			done <- "wrong unavailable count"
		}
	}()
	<-entered
	ifaces[0].Zone = "b"
	if err := e.SetTelemetryInterfaces(ctx, ifaces); err != nil {
		t.Fatal(err)
	}
	releaseRead()
	if reason := <-done; reason != "accounting changed during read" {
		t.Fatal(reason)
	}
}
