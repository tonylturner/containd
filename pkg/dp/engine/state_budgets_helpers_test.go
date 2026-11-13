// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type stateBudgetClock struct{ nanos atomic.Int64 }

func (c *stateBudgetClock) now() time.Time          { return time.Unix(0, c.nanos.Load()) }
func (c *stateBudgetClock) advance(d time.Duration) { c.nanos.Add(int64(d)) }

func stateBudgetEngine(tb testing.TB, l limits.Limits, ledger *limits.Ledger, c *stateBudgetClock) *Engine {
	tb.Helper()
	e, err := New(Config{DPIEnabled: true, Capture: capture.Config{Interfaces: []string{"eth0"}}, Limits: l, Ledger: ledger})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(e.Close)
	e.observation.now, e.iec.now, e.deniedTCPNow, e.verdictCache.now = c.now, c.now, c.now, c.now
	e.LoadRules(rules.Snapshot{Default: rules.ActionAllow, Firewall: []rules.Entry{
		{ID: "enforce", Action: rules.ActionAllow, Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}}, ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "enforce"}},
		{ID: "monitor", Action: rules.ActionAllow, Protocols: []rules.Protocol{{Name: "tcp", Port: "1502"}}, ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "monitor"}},
	}})
	return e
}

// Each identity also has a distinct host pair, exercising observational eviction
// alongside flow pressure. The alternate port selects the dedicated
// observation manager; the standard port selects the legacy manager.
func stateBudgetTrace(id int, enforce bool, at time.Time) []capture.Packet {
	port := uint16(1502)
	if enforce {
		port = 502
	}
	trace := observationTrace(port, false)
	client := net.IPv4(10, byte(id>>8), byte(id), 1)
	for i := range trace {
		p := &trace[i]
		if i%2 == 0 {
			p.SrcIP = client
			p.SrcPort = uint16(30000 + id)
		} else {
			p.DstIP = client
			p.DstPort = uint16(30000 + id)
		}
		p.Timestamp = at
		p.Token = capture.NewToken(1, uint32(id*4+i+1))
		p.Queue = policyQueue(client, trace[0].DstIP, trace[0].SrcPort, port, i%2 == 1)
		markHandshake(p)
		if enforce {
			p.HasMark = true
			p.Mark |= markabi.EnforceScopeMark
		}
	}
	return trace
}

func assertStateBudgetCaps(tb testing.TB, e *Engine) limits.Snapshot {
	tb.Helper()
	s := e.StateLimits()
	if s.Budget.InUse < 0 || s.Budget.InUse > s.Budget.Limit || s.Budget.HighWater > s.Budget.Limit {
		tb.Fatalf("inspection cap: %+v", s.Budget)
	}
	var total int64
	for cat, n := range s.Budget.ByCategory {
		if n < 0 {
			tb.Fatalf("negative %s credit: %d", cat, n)
		}
		total += n
	}
	if total != s.Budget.InUse {
		tb.Fatalf("category sum %d != InUse: %+v", total, s.Budget)
	}
	if len(s.Tables) != 12 {
		tb.Fatalf("missing owner: %+v", s.Tables)
	}
	for _, row := range s.Tables {
		if row.Entries < 0 || row.Entries > row.Limit || row.HighWater > row.Limit || row.ChargedBytes < 0 {
			tb.Fatalf("table cap: %+v", row)
		}
	}
	return s
}

func assertStateBudgetEmpty(tb testing.TB, b *limits.Budget) {
	tb.Helper()
	s := b.Status()
	if s.InUse != 0 {
		tb.Errorf("teardown leaked credit: %+v", s)
	}
	for cat, n := range s.ByCategory {
		if n != 0 {
			tb.Errorf("teardown %s credit = %d", cat, n)
		}
	}
}

type stateBudgetHit struct {
	table  limits.Table
	reason limits.Reason
	mode   limits.Mode
}

func assertStateBudgetHits(tb testing.TB, e *Engine, want map[stateBudgetHit]uint64) {
	tb.Helper()
	got := map[stateBudgetHit]uint64{}
	for _, row := range e.StateLimits().Tables {
		for _, h := range row.Hits {
			got[stateBudgetHit{row.Table, h.Reason, h.Mode}] = h.Total
		}
	}
	if len(got) != len(want) {
		tb.Fatalf("ledger rows: got %v, want %v", got, want)
	}
	for key, n := range want {
		if got[key] != n {
			tb.Fatalf("ledger: got %v, want %v", got, want)
		}
	}
}
