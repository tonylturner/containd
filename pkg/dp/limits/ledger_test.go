// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"sync"
	"testing"
	"time"
)

func TestLedgerPressureTransitionsAndLifetime(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewLedger(func() time.Time { return now })
	o := Occupancy{Limit: 5, Entries: 2, ChargedBytes: 30, HighWater: 4}
	s := l.Status(TableFlows, o)
	if s.Pressure || len(s.Hits) != 0 || s.Limit != 5 || s.Entries != 2 || s.ChargedBytes != 30 || s.HighWater != 4 {
		t.Fatalf("initial %+v", s)
	}
	l.Record(TableFlows, ReasonRefused, ModeEnforce)
	l.Record(TableFlows, ReasonRefused, ModeEnforce)
	l.Record(TableFlows, ReasonEvicted, ModeObserve)
	ts := l.TakeTransitions()
	if len(ts) != 1 || ts[0] != (Transition{TableFlows, ReasonRefused, ModeEnforce}) || len(l.TakeTransitions()) != 0 {
		t.Fatalf("transitions %+v", ts)
	}
	s = l.Status(TableFlows, o)
	if !s.Pressure || len(s.Hits) != 2 || s.Hits[0].Total != 2 || s.Hits[1].Total != 1 {
		t.Fatalf("hits %+v", s)
	}
	now = now.Add(time.Minute - time.Nanosecond)
	l.Record(TableFlows, ReasonRefused, ModeMonitor)
	if len(l.TakeTransitions()) != 0 {
		t.Fatal("transition inside interval")
	}
	now = now.Add(time.Nanosecond)
	l.Record(TableFlows, ReasonRefused, ModeMonitor)
	if ts = l.TakeTransitions(); len(ts) != 0 {
		t.Fatalf("continuous pressure reentered: %+v", ts)
	}
	now = now.Add(time.Minute)
	if l.Status(TableFlows, o).Pressure {
		t.Fatal("pressure did not expire")
	}
	l.Record(TableFlows, ReasonTruncated, ModeObserve)
	if !l.Status(TableFlows, o).Pressure || len(l.TakeTransitions()) != 1 {
		t.Fatal("pressure reentry")
	}
	if l.Status(TableFlows, o).Hits[0].Total != 2 {
		t.Fatal("lifetime totals reset")
	}
	l.Record(Table("invalid"), ReasonRefused, ModeEnforce)
	l.Record(TableFlows, Reason("invalid"), ModeEnforce)
	l.Record(TableFlows, ReasonRefused, Mode("invalid"))
	if len(l.TakeTransitions()) != 0 || l.Status(Table("invalid"), o).Pressure {
		t.Fatal("invalid labels admitted")
	}
}
func TestLedgerAllLabels(t *testing.T) {
	l := NewLedger(nil)
	for _, table := range tables {
		for _, r := range reasons {
			for _, m := range modes {
				l.Record(table, r, m)
			}
		}
		s := l.Status(table, Occupancy{})
		if !s.Pressure || len(s.Hits) != 9 {
			t.Fatalf("%s: %+v", table, s)
		}
		for _, h := range s.Hits {
			if h.Total != 1 {
				t.Fatal("bad count")
			}
		}
	}
	if len(l.TakeTransitions()) != len(tables) {
		t.Fatal("missing tables")
	}
}
func TestLedgerConcurrentRecordAndDrain(t *testing.T) {
	l := NewLedger(func() time.Time { return time.Unix(0, 0) })
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 1000 {
				l.Record(TableInspection, ReasonRefused, ModeMonitor)
			}
		})
	}
	var transitions int
	wg.Go(func() {
		for range 1000 {
			transitions += len(l.TakeTransitions())
			l.Status(TableInspection, Occupancy{})
		}
	})
	wg.Wait()
	transitions += len(l.TakeTransitions())
	s := l.Status(TableInspection, Occupancy{})
	if transitions != 1 || len(s.Hits) != 1 || s.Hits[0].Total != 16000 {
		t.Fatalf("transitions %d status %+v", transitions, s)
	}
}
