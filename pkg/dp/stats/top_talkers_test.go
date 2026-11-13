// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"
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
	if all.Semantics != "recent" || all.Limit != 0 || all.Evicted != 0 || !all.Complete || all.Retained != 20 || all.Since.Before(before) || all.Since.After(after) {
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
	if o := tr.LimitOccupancy(); o.Limit != 0 || o.Entries != 20 {
		t.Fatalf("occupancy %+v", o)
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
