// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/enforce"
)

const transportZoneInterval = 5 * time.Second

type zoneSetterReader interface {
	ZoneSetters(context.Context) ([]enforce.ZoneSetter, error)
}

// An odd generation is unverified; a successful whole-namespace read makes it
// even. Every refresh invalidates previously cached CT evidence first.
type transportAuthority struct {
	checkMu sync.Mutex
	version atomic.Uint64
	loss    atomic.Uint64
	reader  zoneSetterReader
	mu      sync.Mutex
	status  TransportStatus
}

// TransportStatus is observation health, not an enforcement readiness gate.
type TransportStatus struct {
	ZoneStatus    string               `json:"zoneStatus"`
	ZoneCheckedAt time.Time            `json:"zoneCheckedAt,omitempty"`
	ZoneError     string               `json:"zoneError,omitempty"`
	ZoneSetters   []enforce.ZoneSetter `json:"zoneSetters,omitempty"`
	Counters      map[string]uint64    `json:"counters"`
	Modbus        anomaly.PairingStats `json:"modbus"`
}

func newTransportAuthority(reader zoneSetterReader) *transportAuthority {
	a := &transportAuthority{reader: reader, status: TransportStatus{
		ZoneStatus: "zone_unverified", Counters: make(map[string]uint64),
	}}
	a.version.Store(1)
	return a
}

func (a *transportAuthority) invalidate() {
	v := a.version.Load()
	if v%2 == 0 {
		a.version.Add(1)
	} else {
		a.version.Add(2)
	}
}

func (a *transportAuthority) check(ctx context.Context) {
	a.checkMu.Lock()
	defer a.checkMu.Unlock()
	a.checkLocked(ctx)
}

func (a *transportAuthority) checkLocked(ctx context.Context) {
	a.invalidate()
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	var setters []enforce.ZoneSetter
	var err error
	if a.reader == nil {
		err = fmt.Errorf("applier has no zone authority reader")
	} else {
		setters, err = a.reader.ZoneSetters(ctx)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status.ZoneCheckedAt = time.Now().UTC()
	a.status.ZoneSetters = append([]enforce.ZoneSetter(nil), setters...)
	a.status.ZoneError = ""
	a.status.ZoneStatus = "zone_unverified"
	a.status.Counters["zone_checks"]++
	if err != nil {
		a.loss.Add(1)
		a.status.ZoneError = err.Error()
		a.status.Counters["zone_read_errors"]++
	} else if len(setters) != 0 {
		a.loss.Add(1)
		a.status.ZoneStatus = "unsupported_zone"
		a.status.Counters["zone_setter_checks"]++
	} else {
		a.version.Add(1)
		a.status.ZoneStatus = "verified"
	}
}

func (a *transportAuthority) count(name string) {
	a.mu.Lock()
	a.status.Counters[name]++
	a.mu.Unlock()
}

func (a *transportAuthority) snapshot() TransportStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.status
	out.ZoneSetters = append([]enforce.ZoneSetter(nil), out.ZoneSetters...)
	out.Counters = make(map[string]uint64, len(a.status.Counters))
	for k, v := range a.status.Counters {
		out.Counters[k] = v
	}
	return out
}

// Wrapping the engine-owned applier covers full installs, gate switches,
// schedule reconciliation and table release without globals or policy edits.
type transportApplier struct {
	enforce.Applier
	authority *transportAuthority
}

func (a *transportApplier) Apply(ctx context.Context, ruleset string) error {
	a.authority.checkMu.Lock()
	defer a.authority.checkMu.Unlock()
	a.authority.invalidate()
	err := a.Applier.Apply(ctx, ruleset)
	a.authority.checkLocked(ctx)
	return err
}

func (a *transportApplier) ReadCounters(ctx context.Context, table string) (map[string]enforce.CounterValue, error) {
	if reader, ok := a.Applier.(enforce.CounterReader); ok {
		return reader.ReadCounters(ctx, table)
	}
	return nil, fmt.Errorf("applier has no counter reader")
}
