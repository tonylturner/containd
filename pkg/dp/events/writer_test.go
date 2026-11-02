// SPDX-License-Identifier: Apache-2.0

package events

import (
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestWriterStampsEveryPublication(t *testing.T) {
	s := NewStore(8)
	w := s.Writer(telemetry.OriginDemo)
	if w.Store() != s || w.Origin() != telemetry.OriginDemo {
		t.Fatal("writer lost its store or provenance")
	}
	w.Append(Event{Origin: telemetry.OriginReal, Kind: "ids.alert"})
	w.Record(nil, nil, []dpi.Event{{Kind: "decoder"}})
	for _, ev := range s.List(0) {
		if ev.Origin != telemetry.OriginDemo {
			t.Fatalf("unstamped event: %+v", ev)
		}
	}
	counts := s.TelemetryCounts()
	if counts[0].Total != 0 || counts[1].Total != 2 {
		t.Fatalf("counted before stamping: %+v", counts)
	}
	if page := s.ReadFeed(FeedRequest{}); len(page.Records) != 2 || page.Records[0].Event.Origin != telemetry.OriginDemo {
		t.Fatalf("feed provenance: %+v", page)
	}
}

func TestDemoSaturationPreservesRealRetention(t *testing.T) {
	s := NewStore(4)
	s.Append(Event{FlowID: "ordinary", Kind: "real"})
	deny := s.Append(Event{Kind: "firewall.rule.hit", Attributes: map[string]any{"action": "DENY"}})
	incident := s.Append(iecRow("real-session", "ics.session", map[string]any{"outcome": "aborted"}))
	general := append([]Event(nil), s.general.events...)
	denies := append([]Event(nil), s.denies.events...)
	w := s.Writer(telemetry.OriginDemo)
	for i := 0; i < 4*demoCapacity; i++ {
		w.Append(Event{Kind: "firewall.rule.hit", Attributes: map[string]any{"action": "DENY"}})
		w.Append(iecRow("demo-session", "ics.session", map[string]any{"outcome": "aborted"}))
	}
	if !reflect.DeepEqual(general, s.general.events) || !reflect.DeepEqual(denies, s.denies.events) {
		t.Fatal("demo evicted real general or deny evidence")
	}
	if len(s.demo.events) != demoCapacity || len(s.incidents.groups) != 1 || s.incidents.groups["real-session"] == nil {
		t.Fatal("demo entered incident bank or escaped its bound")
	}
	seen := map[uint64]bool{}
	for _, ev := range s.ListTelemetry(0) {
		seen[ev.ID] = true
	}
	if !seen[deny.ID] || !seen[incident.ID] || s.ListTelemetry(1)[0].Origin == telemetry.OriginDemo {
		t.Fatal("demo displaced priority real evidence")
	}
	if len(s.bindings) > demoCapacity+len(general) {
		t.Fatal("demo binding retention is unbounded")
	}
}

func TestDemoReadersMergeByTime(t *testing.T) {
	s := NewStore(8)
	w := s.Writer(telemetry.OriginDemo)
	late := s.Append(Event{FlowID: "late", Timestamp: time.Unix(30, 0)})
	early := w.Append(Event{FlowID: "early", Timestamp: time.Unix(10, 0)})
	mid := s.Append(Event{FlowID: "middle", Timestamp: time.Unix(20, 0)})
	list := s.List(0)
	if len(list) != 3 || list[0].ID != late.ID || list[1].ID != mid.ID || list[2].ID != early.ID {
		t.Fatalf("List order: %+v", list)
	}
	matching := s.MatchingEvents(func(Event) bool { return true })
	if len(matching) != 3 || matching[0].ID != early.ID || matching[2].ID != late.ID {
		t.Fatalf("MatchingEvents order: %+v", matching)
	}
	oldest, newest := s.TimeRange()
	if !oldest.Equal(early.Timestamp) || !newest.Equal(late.Timestamp) {
		t.Fatalf("TimeRange: %v %v", oldest, newest)
	}
	if got := s.Flows(0); len(got) != 3 || got[0].FlowID != "early" || got[2].FlowID != "late" {
		t.Fatalf("Flows order: %+v", got)
	}
	if got := s.QueryTelemetry(Query{}).Events; len(got) != 3 || got[0].ID != late.ID || got[2].ID != early.ID {
		t.Fatalf("QueryTelemetry: %+v", got)
	}
}

func TestFlowAndSessionProvenanceIsolation(t *testing.T) {
	for _, session := range []string{"", "same-session"} {
		t.Run(session, func(t *testing.T) {
			s := NewStore(8)
			real := s.Writer("")
			demo := s.Writer(telemetry.OriginDemo)
			for _, w := range []*Writer{real, demo} {
				w.Append(Event{FlowID: "same-flow", TransportConnectionID: "same-connection", Proto: "iec104", Kind: "request",
					Attributes: map[string]any{"session_id": session}})
			}
			demo.Append(Event{FlowID: "same-flow", TransportConnectionID: "same-connection", Proto: "identify", Kind: "identification",
				Attributes: map[string]any{"protocol": "cip", "identification_state": "confirmed"}})
			flows := s.Flows(0)
			want := 2
			if session != "" {
				want = 3
			}
			if len(flows) != want {
				t.Fatalf("cross-origin grouping: %+v", flows)
			}
			for _, f := range flows {
				if f.Origin != telemetry.OriginDemo && (f.Application != "iec104" || f.Identification != nil) {
					t.Fatalf("demo identification leaked: %+v", f)
				}
			}
			if session != "" {
				demo.MarkAborted(session)
				retainedReal := false
				for _, f := range s.Flows(0) {
					if f.SessionID == session && f.Origin == telemetry.OriginDemo {
						t.Fatal("demo abort failed")
					}
					retainedReal = retainedReal || f.SessionID == session && f.Origin != telemetry.OriginDemo
				}
				if !retainedReal {
					t.Fatal("demo abort hid real session")
				}
				real.MarkAborted(session)
				for _, f := range s.Flows(0) {
					if f.SessionID == session {
						t.Fatal("real abort failed")
					}
				}
			}
		})
	}
}
