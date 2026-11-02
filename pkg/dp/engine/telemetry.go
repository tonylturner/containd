// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"
	"sync/atomic"

	wire "github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/stats"
	"github.com/tonylturner/containd/pkg/dp/telemetry"
)

// accountingView is immutable. Publishing a transition before changing the
// kernel and checking identity after a read prevents new counters/old epochs.
type accountingView struct {
	build  *enforce.Accounting
	reader enforce.AccountingReader
	reason string
}

type counterState struct {
	membership atomic.Pointer[telemetry.Membership]
	tracker    atomic.Pointer[stats.Tracker]
}

// TelemetryMembership returns the immutable last successful interface set.
func (e *Engine) TelemetryMembership() *telemetry.Membership { return e.counters.membership.Load() }

// TelemetryTracker returns the current tracker without waiting for reconfiguration.
func (e *Engine) TelemetryTracker() *stats.Tracker { return e.counters.tracker.Load() }

// SetTelemetryInterfaces records successful OS applies independently of ownership
// reconciliation. Accounting failures are telemetry faults, not interface failures.
func (e *Engine) SetTelemetryInterfaces(ctx context.Context, ifaces []config.Interface) error {
	m := telemetry.Bind(ifaces)
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	e.counters.membership.Store(m)
	g := e.gate
	g.mu.Lock()
	defer g.mu.Unlock()
	g.membership = m
	if g.comp == nil {
		return nil
	}
	if g.accounting.Matches(g.comp.DynamicTable(), m.Zones()) {
		return nil
	}
	g.accountingStatus.Store(&accountingView{reason: "accounting rebuilding"})
	build := enforce.NewAccounting(g.comp.DynamicTable(), m.Zones())
	script, err := build.Script()
	if err == nil {
		err = g.applier.Apply(ctx, script)
	}
	if err != nil {
		g.accounting = nil
		g.accountingStatus.Store(&accountingView{reason: err.Error()})
		return err
	}
	g.publishAccounting(build, g.applier)
	return nil
}

func (g *envelopeGate) publishAccounting(build *enforce.Accounting, applier enforce.Applier) {
	g.accounting = build
	reader, _ := applier.(enforce.AccountingReader)
	g.accountingStatus.Store(&accountingView{build: build, reader: reader})
}

// TelemetryConduits never waits for a policy or lifecycle lock.
func (e *Engine) TelemetryConduits(ctx context.Context) ([]wire.CounterSample, []wire.SourceUnavailable) {
	unavailable := func(reason string) ([]wire.CounterSample, []wire.SourceUnavailable) {
		return nil, []wire.SourceUnavailable{{Source: "conduit", Reason: reason}}
	}
	if e.TelemetryMembership() == nil {
		return unavailable("interfaces not applied")
	}
	v := e.gate.accountingStatus.Load()
	if v == nil {
		return unavailable("rules not applied")
	}
	if v.reason != "" {
		return unavailable(v.reason)
	}
	if v.reader == nil {
		return unavailable("accounting reader unavailable")
	}
	values, err := v.reader.ReadAccountingCounters(ctx, v.build.Table)
	if e.gate.accountingStatus.Load() != v {
		return unavailable("accounting changed during read")
	}
	if err != nil {
		return unavailable(err.Error())
	}
	var samples []wire.CounterSample
	var missing []wire.SourceUnavailable
	for _, pair := range v.build.Pairs {
		dims := map[string]string{"from": pair.From, "to": pair.To}
		value, ok := values[pair.Counter]
		for _, c := range []struct {
			metric wire.Metric
			value  uint64
		}{{wire.ConduitBytes, value.Bytes}, {wire.ConduitPackets, value.Packets}} {
			if !ok {
				missing = append(missing, wire.SourceUnavailable{Source: "conduit", Metric: c.metric, Dims: dims, Reason: fmt.Sprintf("counter %s missing", pair.Counter)})
			} else {
				samples = append(samples, wire.CounterSample{Metric: c.metric, Dims: dims, Value: c.value, Epoch: v.build.Epoch, Origin: wire.OriginReal})
			}
		}
	}
	return samples, missing
}

// Transport authority wraps the install path but does not own these counters.
func (a *transportApplier) ReadAccountingCounters(ctx context.Context, table string) (map[string]enforce.CounterValue, error) {
	reader, ok := a.Applier.(enforce.AccountingReader)
	if !ok {
		return nil, fmt.Errorf("applier has no accounting reader")
	}
	return reader.ReadAccountingCounters(ctx, table)
}
