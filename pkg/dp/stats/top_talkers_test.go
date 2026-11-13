// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/limits"
)

func TestTopTalkersMetadataAndSelection(t *testing.T) {
	if o := (*Tracker)(nil).LimitOccupancy(); o.Entries != 0 || o.Limit != 0 {
		t.Fatalf("nil occupancy %+v", o)
	}
	before := time.Now()
	tr := New()
	after := time.Now()
	for i := 20; i > 0; i-- {
		tr.RecordPacket(netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", i)), netip.MustParseAddr("192.0.2.100"), "tcp", i%3, time.Now())
	}
	all := tr.TopTalkers(0)
	if all.Semantics != "recent" || all.Limit != limits.DefaultMaxTopTalkers || all.Evicted != 0 || !all.Complete || all.Retained != 20 || all.Since.Before(before) || all.Since.After(after) {
		t.Fatalf("metadata %+v", all)
	}
	for _, n := range []int{-1, 0, 1, 5, 20, 1000} {
		got := tr.TopTalkers(n)
		want := len(all.Rows)
		if n > 0 {
			want = min(want, n)
		}
		if !reflect.DeepEqual(got.Rows, all.Rows[:want]) || got.Retained != 20 {
			t.Fatalf("top %d: %+v", n, got)
		}
	}
	for i := 1; i < len(all.Rows); i++ {
		if !talkerBefore(all.Rows[i-1], all.Rows[i]) {
			t.Fatal("unstable ties")
		}
	}
	all.Rows[0].Bytes = 999
	if tr.TopTalkers(1).Rows[0].Bytes == 999 {
		t.Fatal("snapshot aliases owner")
	}
	if o := tr.LimitOccupancy(); o.Limit != limits.DefaultMaxTopTalkers || o.Entries != 20 || o.HighWater != 20 {
		t.Fatalf("occupancy %+v", o)
	}
}

func TestTopTalkerLRUAndExactRetainedCounts(t *testing.T) {
	tr := New()
	configured := limits.Default()
	configured.MaxTopTalkers = 4
	ledger := limits.NewLedger(nil)
	tr.SetLimits(configured, limits.NewBudget(1), ledger)
	dst := netip.MustParseAddr("198.51.100.1")
	for i := 0; i < 44; i++ {
		src := netip.AddrFrom4([4]byte{10, byte(i / 256), byte(i), 1})
		tr.RecordPacket(src, dst, "tcp", i+1, time.Now())
	}
	all := tr.TopTalkers(0)
	if all.Limit != 4 || all.Retained != 4 || all.Evicted != 40 || all.Complete {
		t.Fatalf("retention metadata %+v", all)
	}
	for _, row := range all.Rows {
		if row.SrcIP < "10.0.40.1" {
			t.Fatalf("old row survived LRU eviction: %+v", row)
		}
	}
	retained := netip.MustParseAddr("10.0.43.1")
	tr.RecordPacket(retained, dst, "tcp", 1, time.Now())
	for _, row := range tr.TopTalkers(0).Rows {
		if row.SrcIP == retained.String() && (row.Packets != 2 || row.Bytes != 45) {
			t.Fatalf("retained row counters %+v", row)
		}
	}
	hits := ledger.Status(limits.TableTopTalkers, limits.Occupancy{}).Hits
	if len(hits) != 1 || hits[0].Reason != limits.ReasonEvicted || hits[0].Mode != limits.ModeObserve || hits[0].Total != 40 {
		t.Fatalf("top-talker ledger hits %+v", hits)
	}
	if o := tr.LimitOccupancy(); o.Limit != 4 || o.Entries != 4 || o.HighWater != 4 {
		t.Fatalf("top-talker occupancy %+v", o)
	}
}

func TestProtocolStatsAreCappedIntoOther(t *testing.T) {
	tr := New()
	src, dst := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	for i := 0; i < limits.MaxProtocols+16; i++ {
		tr.RecordPacket(src, dst, fmt.Sprintf("proto-%02d", i), 1, time.Now())
	}
	stats := tr.Stats()
	if len(stats) != limits.MaxProtocols {
		t.Fatalf("protocol stats entries %d, want %d", len(stats), limits.MaxProtocols)
	}
	foundOther := false
	for _, stat := range stats {
		if stat.Protocol == "other" {
			foundOther = true
			if stat.PacketCount != 17 {
				t.Fatalf("other aggregate = %d packets, want 17", stat.PacketCount)
			}
		}
	}
	if !foundOther {
		t.Fatal("protocol overflow bucket missing")
	}
	for _, row := range tr.TopTalkers(0).Rows {
		if row.Protocol == "" {
			t.Fatal("empty protocol key")
		}
	}
}
func TestTalkerDeterministicTies(t *testing.T) {
	rows := []FlowStats{
		{SrcIP: "b", DstIP: "a", Protocol: "a", Bytes: 1},
		{SrcIP: "a", DstIP: "b", Protocol: "a", Bytes: 1},
		{SrcIP: "a", DstIP: "a", Protocol: "b", Bytes: 1},
		{SrcIP: "a", DstIP: "a", Protocol: "a", Bytes: 1},
	}
	for i := range rows {
		for j := i + 1; j < len(rows); j++ {
			if !talkerBefore(rows[j], rows[i]) || talkerBefore(rows[i], rows[j]) {
				t.Fatal("tie ordering")
			}
		}
	}
	h := talkerHeap{rows[0]}
	if h.Pop().(FlowStats) != rows[0] || h.Len() != 0 {
		t.Fatal("heap pop")
	}
}
