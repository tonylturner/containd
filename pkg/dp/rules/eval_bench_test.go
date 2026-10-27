// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package rules

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// benchPolicy has n ALLOW rules on distinct source networks; only the last
// one holds benchContext.
func benchPolicy(n int) *Snapshot {
	snap := &Snapshot{Default: ActionDeny}
	for i := range n {
		snap.Firewall = append(snap.Firewall, Entry{
			ID:           "r" + strconv.Itoa(1000+i),
			SourceZones:  []string{"control"},
			Sources:      []string{"10." + strconv.Itoa(i) + ".0.0/16", "192.168." + strconv.Itoa(i) + ".0/24"},
			Destinations: []string{"2001:db8::/32", "172.16.0.0/12"},
			Protocols:    []Protocol{{Name: "tcp", Port: "502"}},
			Action:       ActionAllow,
		})
	}
	return snap
}

func benchContext(n int) EvalContext {
	return EvalContext{
		SrcZone: "control",
		SrcIP:   net.IPv4(10, byte(n-1), 0, 5),
		DstIP:   net.IPv4(172, 16, 0, 9),
		Proto:   "tcp",
		Port:    "502",
	}
}

// BenchmarkEvaluateMatch decides a packet that only the last of 16 rules
// allows.
func BenchmarkEvaluateMatch(b *testing.B) {
	const n = 16
	ev := NewEvaluator(benchPolicy(n))
	ctx := benchContext(n)
	b.ReportAllocs()
	for b.Loop() {
		if _, entry := ev.EvaluateMatch(ctx); entry == nil {
			b.Fatal("no rule matched")
		}
	}
}

// BenchmarkEvaluateMatchScheduled decides a packet that a scheduled ALLOW
// in a named timezone admits, inside its window.
func BenchmarkEvaluateMatchScheduled(b *testing.B) {
	snap := benchPolicy(1)
	snap.Firewall[0].Schedule = SchedulePredicate{
		DaysOfWeek: []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"},
		StartTime:  "22:00", EndTime: "06:00", Timezone: "America/New_York",
	}
	ev := NewEvaluator(snap)
	ctx := benchContext(1)
	ctx.Now = time.Date(2026, 10, 27, 3, 30, 0, 0, time.UTC) // Monday 23:30 in New York
	b.ReportAllocs()
	for b.Loop() {
		if _, entry := ev.EvaluateMatch(ctx); entry == nil {
			b.Fatal("no rule matched")
		}
	}
}
