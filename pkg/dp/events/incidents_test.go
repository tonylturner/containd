package events

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func iecRow(session, kind string, attrs map[string]any) Event {
	attrs["session_id"] = session
	return Event{Proto: "iec104", Kind: kind, Attributes: attrs, Timestamp: time.Unix(100, 0), Transport: "tcp", SrcIP: "192.0.2.1", DstIP: "192.0.2.2", DstPort: 2404}
}

func TestIncidentCausalEvidenceUnderPressure(t *testing.T) {
	for _, decodedFirst := range []bool{true, false} {
		t.Run(fmt.Sprint(decodedFirst), func(t *testing.T) {
			s := NewStore(8)
			attempt := iecRow("session-a", "request", map[string]any{"apdu_id": "session-a/c/1", "type_id": 45, "ca": 1, "ioa": 2002, "class": "control", "value": true})
			var want []Event
			if decodedFirst {
				want = append(want, s.Append(attempt))
			}
			want = append(want, s.Append(iecRow("session-a", "ics.decision", map[string]any{"decision": "deny", "action": "DENY", "mode": "enforce", "apdu_id": "session-a/c/1", "type_id": 45, "ca": 1, "ioa": 2002})))
			if !decodedFirst {
				want = append(want, s.Append(attempt))
			}
			for _, outcome := range []string{"dropped", "drop_failed", "aborted", "reset_sent", "reset_failed"} {
				kind := "ics.session"
				if outcome == "dropped" || outcome == "drop_failed" {
					kind = "ics.verdict"
				}
				want = append(want, s.Append(iecRow("session-a", kind, map[string]any{"outcome": outcome, "apdu_ids": []string{"session-a/c/1"}, "trigger_apdu_id": "session-a/c/1"})))
			}
			for i := 0; i < 10000; i++ {
				s.Append(iecRow("session-a", "response", map[string]any{"apdu_id": fmt.Sprintf("session-a/s/%d", i), "type_id": 1, "class": "monitor"}))
				s.Append(iecRow("session-a", "ics.decision", map[string]any{"decision": "allow", "apdu_id": fmt.Sprint(i)}))
			}
			got := s.ListTelemetry(0)
			byID := map[uint64]Event{}
			for _, e := range got {
				if _, ok := byID[e.ID]; ok {
					t.Fatal("duplicate ID")
				}
				byID[e.ID] = e
			}
			for _, e := range want {
				if !reflect.DeepEqual(e, byID[e.ID]) {
					t.Fatalf("causal evidence lost or changed: %+v", e)
				}
			}
			if n := len(s.incidents.groups["session-a"].events); n != len(want) {
				t.Fatalf("pinned ordinary objects: %d", n)
			}
			if s.Len() != 8 {
				t.Fatal("general capacity changed")
			}
		})
	}
}

func TestIncidentBounds(t *testing.T) {
	s := NewStore(1)
	for i := 0; i < incidentCapacity+1; i++ {
		s.Append(iecRow(fmt.Sprint(i), "ics.session", map[string]any{"outcome": "aborted"}))
	}
	if len(s.incidents.groups) != incidentCapacity || s.incidents.groups["0"] != nil {
		t.Fatal("bundle overflow")
	}
	for i := 0; i < incidentRows+2; i++ {
		s.Append(iecRow("1", "ics.session", map[string]any{"outcome": "reset_failed"}))
	}
	if len(s.incidents.groups["1"].events) != incidentRows || !s.historyTruncated {
		t.Fatal("row overflow")
	}
}
