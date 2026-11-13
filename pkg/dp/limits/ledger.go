// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"sync/atomic"
	"time"
)

type Table string

const (
	TableFlows            Table = "flows"
	TableInspection       Table = "inspection_bytes"
	TableTopTalkers       Table = "top_talkers"
	TableRateTrackers     Table = "rate_trackers"
	TableIECSessions      Table = "iec_sessions"
	TableIECReconnect     Table = "iec_reconnect_history"
	TableInventoryPoints  Table = "inventory_points"
	TableSignatureWindows Table = "signature_windows"
	TableConformance      Table = "conformance_connections"
	TableVerdictCache     Table = "verdict_cache"
	TablePickupReset      Table = "pickup_reset"
	TableHTTPCorrelation  Table = "http_correlation"
)

var tables = [...]Table{TableFlows, TableInspection, TableTopTalkers, TableRateTrackers, TableIECSessions, TableIECReconnect, TableInventoryPoints, TableSignatureWindows, TableConformance, TableVerdictCache, TablePickupReset, TableHTTPCorrelation}
var tableIndex = func() map[Table]int {
	m := make(map[Table]int, len(tables))
	for i, t := range tables {
		m[t] = i
	}
	return m
}()

type Reason string

const (
	ReasonRefused   Reason = "refused"
	ReasonEvicted   Reason = "evicted"
	ReasonTruncated Reason = "truncated"
)

type Mode string

const (
	ModeEnforce Mode = "enforce"
	ModeMonitor Mode = "monitor"
	ModeObserve Mode = "observe"
)

var reasons = [...]Reason{ReasonRefused, ReasonEvicted, ReasonTruncated}
var modes = [...]Mode{ModeEnforce, ModeMonitor, ModeObserve}

type Occupancy struct{ Limit, Entries, ChargedBytes, HighWater int64 }
type Hit struct {
	Reason Reason `json:"reason"`
	Mode   Mode   `json:"mode"`
	Total  uint64 `json:"total"`
}
type TableStatus struct {
	Table        Table `json:"table"`
	Limit        int64 `json:"limit"`
	Entries      int64 `json:"entries"`
	ChargedBytes int64 `json:"chargedBytes"`
	HighWater    int64 `json:"highWater"`
	Pressure     bool  `json:"pressure"`
	Hits         []Hit `json:"hits"`
}
type Snapshot struct {
	Tables []TableStatus `json:"tables"`
	Budget BudgetStatus  `json:"budget"`
}

// Transition identifies the first hit in a table's pressure interval. The owner
// supplies the current limit when publishing the event, outside its locks.
type Transition struct {
	Table  Table
	Reason Reason
	Mode   Mode
}
type ledgerRow struct {
	hits [9]atomic.Uint64
	// last is a non-nil timestamp even when the injected clock is at the epoch.
	last    atomic.Pointer[time.Time]
	pending atomic.Uint32
}
type Ledger struct {
	now  func() time.Time
	rows [len(tables)]ledgerRow
}

func NewLedger(now func() time.Time) *Ledger {
	if now == nil {
		now = time.Now
	}
	return &Ledger{now: now}
}
func hitIndex(r Reason, m Mode) (int, bool) {
	ri, mi := -1, -1
	switch r {
	case ReasonRefused:
		ri = 0
	case ReasonEvicted:
		ri = 1
	case ReasonTruncated:
		ri = 2
	}
	switch m {
	case ModeEnforce:
		mi = 0
	case ModeMonitor:
		mi = 1
	case ModeObserve:
		mi = 2
	}
	return ri*3 + mi, ri >= 0 && mi >= 0
}

// Record performs bounded atomic accounting only. The injected clock must be
// concurrency-safe and non-blocking; no observer or event callback is invoked.
func (l *Ledger) Record(t Table, r Reason, m Mode) {
	i, ok := tableIndex[t]
	h, valid := hitIndex(r, m)
	if !ok || !valid {
		return
	}
	row := &l.rows[i]
	row.hits[h].Add(1)
	now := l.now()
	for old := row.last.Load(); old == nil || now.After(*old); old = row.last.Load() {
		if row.last.CompareAndSwap(old, &now) {
			if old == nil || now.Sub(*old) >= time.Minute {
				row.pending.CompareAndSwap(0, uint32(h+1))
			}
			break
		}
	}
}
func (l *Ledger) TakeTransitions() []Transition {
	var out []Transition
	for i, t := range tables {
		if h := l.rows[i].pending.Swap(0); h > 0 {
			n := int(h) - 1
			out = append(out, Transition{t, reasons[n/3], modes[n%3]})
		}
	}
	return out
}
func (l *Ledger) Status(t Table, o Occupancy) TableStatus {
	s := TableStatus{Table: t, Limit: o.Limit, Entries: o.Entries, ChargedBytes: o.ChargedBytes, HighWater: o.HighWater, Hits: []Hit{}}
	i, ok := tableIndex[t]
	if !ok {
		return s
	}
	row := &l.rows[i]
	if last := row.last.Load(); last != nil {
		s.Pressure = l.now().Sub(*last) < time.Minute
	}
	for h := range row.hits {
		if n := row.hits[h].Load(); n > 0 {
			s.Hits = append(s.Hits, Hit{reasons[h/3], modes[h%3], n})
		}
	}
	return s
}
