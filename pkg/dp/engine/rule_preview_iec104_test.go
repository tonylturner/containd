// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"encoding/json"
	"testing"
	"time"

	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func previewRule(t *testing.T, events []dpevents.Event, rule string) PreviewRuleResponse {
	t.Helper()
	var entry rules.Entry
	if err := json.Unmarshal([]byte(rule), &entry); err != nil {
		t.Fatal(err)
	}
	e := &Engine{eventStore: dpevents.NewStore(4096)}
	// Append in reverse so the retained newest-first order is fixture order.
	for i := len(events) - 1; i >= 0; i-- {
		events[i].Timestamp = time.Unix(int64(len(events)-i), 0)
		e.eventStore.Append(events[i])
	}
	return e.PreviewRule(entry)
}

func iecEvent(id uint64, kind string, request bool, attrs map[string]any) dpevents.Event {
	ev := dpevents.Event{ID: id, Proto: "iec104", Kind: kind, Transport: "tcp", Attributes: attrs,
		SrcIP: "10.60.60.10", DstIP: "10.30.30.30", SrcPort: 40000, DstPort: 2404}
	if !request {
		ev.SrcIP, ev.DstIP, ev.SrcPort, ev.DstPort = ev.DstIP, ev.SrcIP, ev.DstPort, ev.SrcPort
	}
	return ev
}

// Retain the JSON-number cases from the former management-side preview tests.
func TestPreviewFirewallRuleIEC104(t *testing.T) {
	events := []dpevents.Event{
		iecEvent(1, "request", true, map[string]any{"apci_type": "I", "direction": "request", "class": "control", "type_id": float64(46), "ca": float64(1), "ioa": float64(2001)}),
		iecEvent(2, "request", true, map[string]any{"apci_type": "I", "direction": "request", "class": "control", "type_id": float64(46), "ca": float64(2), "ioa": float64(2001)}),
		iecEvent(3, "response", false, map[string]any{"apci_type": "I", "direction": "response", "class": "control", "type_id": float64(46), "ca": float64(1), "ioa": float64(2001)}),
		iecEvent(4, "ics.decision", true, map[string]any{"decision": "allow", "type_id": float64(46), "ca": float64(1), "ioa": float64(2001), "direction": "request"}),
		iecEvent(5, "request", true, map[string]any{"apci_type": "I", "direction": "request", "class": "control", "type_id": float64(46), "ca": float64(65535), "ioa": float64(2001)}),
		{ID: 6, Proto: "modbus", Kind: "request", Transport: "tcp", SrcIP: "10.60.60.10", DstIP: "10.30.30.30", DstPort: 2404,
			Attributes: map[string]any{"function_code": float64(46)}},
	}
	command := `{"id":"cmd","sources":["10.60.60.10/32"],"destinations":["10.30.30.30/32"],
		"protocols":[{"name":"tcp","port":"2404"}],"action":"ALLOW",
		"ics":{"protocol":"iec104","typeIds":[46],"classes":["control"],"ca":[1],"ioa":[{"start":2001,"end":2001}],"mode":"enforce"}}`
	resp := previewRule(t, events, command)
	if resp.MatchCount != 2 || resp.SampleMatches[0].ID != 1 || resp.SampleMatches[1].ID != 3 {
		t.Fatalf("command rule matched %d events %+v; want events 1 and 3", resp.MatchCount, resp.SampleMatches)
	}

	// The response half matches in the session orientation: source = the
	// client, port = 2404.
	confirm := `{"id":"confirm","sources":["10.60.60.10/32"],"protocols":[{"name":"tcp","port":"2404"}],"action":"ALLOW",
		"ics":{"protocol":"iec104","classes":["control"],"direction":"response"}}`
	resp = previewRule(t, events, confirm)
	if resp.MatchCount != 1 || resp.SampleMatches[0].ID != 3 {
		t.Fatalf("confirm rule matched %d events %+v; want event 3", resp.MatchCount, resp.SampleMatches)
	}

	// Broadcasts (5) are denied before rule matching, even for DENY candidates.
	// Decision events (4) and other protocols (6) never count.
	allow := `{"id":"allow","action":"ALLOW","ics":{"protocol":"iec104","typeIds":[46]}}`
	if resp = previewRule(t, events, allow); resp.MatchCount != 3 {
		t.Fatalf("allow rule matched %d events %+v; want events 1-3", resp.MatchCount, resp.SampleMatches)
	}
	deny := `{"id":"deny","action":"DENY","ics":{"protocol":"iec104","typeIds":[46]}}`
	if resp = previewRule(t, events, deny); resp.MatchCount != 3 {
		t.Fatalf("deny rule matched %d events %+v; want events 1-3", resp.MatchCount, resp.SampleMatches)
	}
}

func TestPreviewFirewallRuleIEC104ReadOnlyUsesDecoderClassification(t *testing.T) {
	events := []dpevents.Event{
		iecEvent(1, "request", true, map[string]any{
			"apci_type": "I", "direction": "request", "class": "system",
			"type_id": float64(100), "ca": float64(1),
		}),
		iecEvent(2, "response", false, map[string]any{
			"apci_type": "I", "direction": "response", "class": "monitor",
			"type_id": float64(1), "ca": float64(1),
		}),
		iecEvent(3, "request", true, map[string]any{
			"apci_type": "I", "direction": "request", "class": "monitor",
			"type_id": float64(1), "ca": float64(1),
		}),
		iecEvent(4, "unsupported", true, map[string]any{
			"apci_type": "I", "direction": "request", "class": "unknown",
			"type_id": float64(2), "ca": float64(1), "error": "type 2 is not in the supported IEC 104 type set",
		}),
		iecEvent(5, "request", true, map[string]any{
			"apci_type": "I", "direction": "request", "class": "system",
			"type_id": float64(100), "ca": float64(65535),
		}),
	}
	rule := `{"id":"read","action":"ALLOW","ics":{"protocol":"iec104","readOnly":true}}`
	resp := previewRule(t, events, rule)
	if resp.MatchCount != 2 || resp.SampleMatches[0].ID != 1 || resp.SampleMatches[1].ID != 2 {
		t.Fatalf("readOnly rule matched %d events %+v; want forward GI and reverse monitor events", resp.MatchCount, resp.SampleMatches)
	}
}
