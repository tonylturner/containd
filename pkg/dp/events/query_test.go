// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package events

import (
	"fmt"
	"net/url"
	"testing"
	"time"
)

func parseTestQuery(t *testing.T, raw string) Query {
	t.Helper()
	v, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatal(err)
	}
	q, _, err := ParseQuery(v)
	if err != nil {
		t.Fatal(err)
	}
	return q
}
func TestQueryFiltersBeforeLimit(t *testing.T) {
	s := NewStore(8)
	denied := s.Append(iecRow("wanted", "ics.decision", map[string]any{"decision": "deny", "action": "DENY", "apdu_id": "wanted/c/1"}))
	for i := 0; i < 10000; i++ {
		s.Append(iecRow("noise", "response", map[string]any{"type_id": 1, "class": "monitor"}))
	}
	for _, raw := range []string{"session=wanted", "flow=wanted", "decision=deny", "verdict=deny", "kind=ics.decision", "apdu=wanted%2Fc%2F1"} {
		q := parseTestQuery(t, raw+"&limit=1&protocol=IEC104&since=1970-01-01T00:01:40Z")
		p := s.QueryTelemetry(q)
		if len(p.Events) != 1 || p.Events[0].ID != denied.ID || !p.HistoryTruncated {
			t.Fatalf("%s: %+v", raw, p)
		}
	}
	if p := s.QueryTelemetry(parseTestQuery(t, "session=wanted&since=1970-01-01T00:01:41Z")); len(p.Events) != 0 {
		t.Fatal("since boundary")
	}
}
func TestQueryCursorTiesAndDeduplication(t *testing.T) {
	s := NewStore(20)
	for i := 0; i < 10; i++ {
		s.Append(iecRow("one", "ics.decision", map[string]any{"decision": "deny"}))
	}
	q := parseTestQuery(t, "session=one&limit=3")
	seen := map[uint64]bool{}
	for {
		p := s.QueryTelemetry(q)
		for _, e := range p.Events {
			if seen[e.ID] {
				t.Fatalf("duplicate %d", e.ID)
			}
			seen[e.ID] = true
		}
		if p.NextCursor == "" {
			break
		}
		q = parseTestQuery(t, "session=one&limit=3&cursor="+url.QueryEscape(p.NextCursor))
	}
	if len(seen) != 10 {
		t.Fatalf("lost rows: %d", len(seen))
	}
}
func TestParseQueryValidationAndRoundTrip(t *testing.T) {
	for _, raw := range []string{"id=0", "id=-1", "id=bad", "id=18446744073709551616", "limit=0", "limit=5001", "limit=bad", "since=yesterday", "cursor=xxx", "category=unknown"} {
		v, _ := url.ParseQuery(raw)
		if _, _, err := ParseQuery(v); err == nil {
			t.Fatal(raw)
		}
	}
	q := parseTestQuery(t, "id=42&session=s&flow=f&kind=ics.&protocol=iec104&decision=deny&verdict=dropped&apdu=a&since=2026-01-01T01:02:03.123Z&limit=42")
	round, filtered, err := ParseQuery(q.Values())
	if err != nil || !filtered || fmt.Sprint(round) != fmt.Sprint(q) {
		t.Fatalf("round trip: %+v %v", round, err)
	}
	for _, raw := range []string{"", "limit=1"} {
		v, _ := url.ParseQuery(raw)
		if _, filtered, err := ParseQuery(v); err != nil || filtered {
			t.Fatalf("legacy changed: %s", raw)
		}
	}
	p := QueryPage([]Event{{ID: 1, Timestamp: time.Now(), Kind: "service.av.detected"}, {ID: 2, Kind: "service.nginx.access"}}, parseTestQuery(t, "detections=1"), false, false)
	if len(p.Events) != 1 || p.Events[0].ID != 1 {
		t.Fatal(p)
	}
}

func TestQueryVerdictOutcomesAndIncidentOverflowWarning(t *testing.T) {
	s := NewStore(10000)
	dropped := s.Append(iecRow("one", "ics.verdict", map[string]any{"outcome": "drop_failed", "apdu_ids": []any{"one/c/1"}}))
	for _, raw := range []string{"verdict=DROP_FAILED", "apdu=one/c/1", "session=one&kind=ics.verdict,"} {
		p := s.QueryTelemetry(parseTestQuery(t, raw))
		if len(p.Events) != 1 || p.Events[0].ID != dropped.ID || p.HistoryTruncated {
			t.Fatalf("%s: %+v", raw, p)
		}
	}
	if p := s.QueryTelemetry(parseTestQuery(t, "protocol=dnp3")); len(p.Events) != 0 {
		t.Fatal("protocol ignored")
	}
	if p := s.QueryTelemetry(parseTestQuery(t, "verdict=dropped")); len(p.Events) != 0 {
		t.Fatal("outcome ignored")
	}
	for i := 0; i < incidentRows; i++ {
		s.Append(iecRow("one", "ics.session", map[string]any{"outcome": "reset_failed"}))
	}
	p := s.QueryTelemetry(parseTestQuery(t, "session=one"))
	if !p.HistoryTruncated || s.Len() != incidentRows+1 {
		t.Fatal("incident row overflow not signaled independently of general ring")
	}
	// Bundle overflow must also signal loss without relying on general overflow.
	s = NewStore(10000)
	for i := 0; i < incidentCapacity+1; i++ {
		s.Append(iecRow(fmt.Sprint(i), "ics.session", map[string]any{"outcome": "aborted"}))
	}
	if !s.QueryTelemetry(Query{}).HistoryTruncated {
		t.Fatal("incident bundle overflow not signaled")
	}
}
