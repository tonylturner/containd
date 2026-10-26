// SPDX-License-Identifier: Apache-2.0

package events

import (
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

// A flow's events carry its TAG labels; the decoder's attribute map is
// not changed.
func TestRecordAddsFlowTags(t *testing.T) {
	s := NewStore(8)
	state := stateOf("192.0.2.1", "192.0.2.2", 40000, 502)
	state.Tags = []string{"any", "plc"}
	attrs := map[string]any{"function_code": 3}
	s.Record(state, &dpi.ParsedPacket{Proto: "tcp"}, []dpi.Event{{Proto: "modbus", Kind: "request", Attributes: attrs, Timestamp: time.Unix(1, 0)}})
	got := s.List(0)[0].Attributes
	if !reflect.DeepEqual(got[KeyTags], []string{"any", "plc"}) || got["function_code"] != 3 {
		t.Fatalf("attributes = %v", got)
	}
	if _, ok := attrs[KeyTags]; ok {
		t.Fatal("the decoder's attributes were changed")
	}
	state.Tags = nil
	s.Record(state, nil, []dpi.Event{{Proto: "modbus", Kind: "request", Attributes: attrs}})
	if _, ok := s.List(0)[0].Attributes[KeyTags]; ok {
		t.Fatal("an untagged flow's event has tags")
	}
}

// A RESET rule hit is kept with the DENYs.
func TestTelemetryBankKeepsResets(t *testing.T) {
	s := NewStore(2)
	reset := s.Append(Event{Kind: "firewall.rule.hit", Attributes: map[string]any{"action": "RESET"}})
	for _, action := range []string{"RATE_LIMIT", "TAG", "ALLOW", "ALLOW", "ALLOW"} {
		s.Append(Event{Kind: "firewall.rule.hit", Attributes: map[string]any{"action": action}})
	}
	if len(s.denies.events) != 1 || s.ListTelemetry(1)[0].ID != reset.ID {
		t.Fatalf("RESET not retained: %+v", s.denies.events)
	}
}

// A flow summary lists the labels its events carry; a flow whose events
// carry none has no tags.
func TestFlowSummaryTags(t *testing.T) {
	s := NewStore(8)
	s.Append(Event{FlowID: "f1", Kind: "firewall.rule.hit", Attributes: WithTags(map[string]any{"action": "TAG"}, []string{"plc", "any"})})
	s.Append(Event{FlowID: "f1", Kind: "firewall.rule.hit", Attributes: WithTags(nil, []string{"any", "ops"})})
	s.Append(Event{FlowID: "f2", Kind: "firewall.rule.hit", Attributes: map[string]any{"action": "DENY"}})
	got := map[string][]string{}
	for _, f := range s.Flows(0) {
		got[f.FlowID] = f.Tags
	}
	if want := map[string][]string{"f1": {"any", "ops", "plc"}, "f2": nil}; !reflect.DeepEqual(got, want) {
		t.Fatalf("flow tags = %v, want %v", got, want)
	}
}
