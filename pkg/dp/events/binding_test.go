// SPDX-License-Identifier: Apache-2.0

package events

import "testing"

func TestFlowBindingRetainedAcrossEviction(t *testing.T) {
	s := NewStore(2)
	add := func(proto, kind string, attrs map[string]any) {
		s.Append(Event{FlowID: "flow", Proto: proto, Kind: kind, Attributes: attrs})
	}
	add("firewall", "firewall.rule.hit", nil)
	add("ssh", "detect", nil)
	if got := s.Flows(0)[0].Application; got != "" {
		t.Fatal(got)
	}
	add("dnp3", "malformed", nil)
	if got := s.Flows(0)[0].Application; got != "dnp3" {
		t.Fatal(got)
	}
	attrs := map[string]any{"protocol": "modbus", "identification_state": "confirmed", "binding": "observation", "mismatch": true, "outside_rule_port_scope": true}
	add("identify", "identification", attrs)
	attrs["protocol"] = "changed by caller"
	for i := 0; i < 5; i++ {
		add("dnp3", "malformed", nil)
	}
	got := s.Flows(0)[0]
	if got.Application != "modbus" || got.Identification["protocol"] != "modbus" {
		t.Fatalf("%+v", got)
	}
	s.Append(Event{FlowID: "other", Proto: "firewall"})
	s.Append(Event{FlowID: "other", Proto: "firewall"})
	if len(s.bindings) != 1 {
		t.Fatalf("leaked records: %+v", s.bindings)
	}
}

func TestFlowSessionBinding(t *testing.T) {
	s := NewStore(2)
	s.Append(Event{FlowID: "wire", Proto: "iec104", Kind: "apci", Attributes: map[string]any{"session_id": "session"}})
	s.Append(Event{FlowID: "wire", Proto: "identify", Kind: "identification", Attributes: map[string]any{"protocol": "iec104", "identification_state": "confirmed", "binding": "legacy"}})
	s.Append(Event{FlowID: "wire", Proto: "iec104", Kind: "apci", Attributes: map[string]any{"session_id": "session"}})
	s.Append(Event{FlowID: "wire", Proto: "iec104", Kind: "apci", Attributes: map[string]any{"session_id": "session"}})
	got := s.Flows(0)[0]
	if got.Application != "iec104" || got.Identification["binding"] != "legacy" {
		t.Fatalf("%+v", got)
	}
}

func TestIncompleteIdentificationKeepsLegacyApplication(t *testing.T) {
	s := NewStore(3)
	s.Append(Event{FlowID: "wire", Proto: "modbus", Kind: "request"})
	s.Append(Event{FlowID: "wire", Proto: "identify", Kind: "identification", Attributes: map[string]any{"protocol": "cip", "identification_state": "identification_incomplete", "binding": "none"}})
	if got := s.Flows(0)[0].Application; got != "modbus" {
		t.Fatal(got)
	}
}

func TestConnectionBindingAcrossDirections(t *testing.T) {
	s := NewStore(4)
	s.Append(Event{FlowID: "forward", TransportConnectionID: "connection", Proto: "identify", Kind: "identification", Attributes: map[string]any{"protocol": "modbus", "identification_state": "confirmed", "binding": "observation"}})
	s.Append(Event{FlowID: "reverse", TransportConnectionID: "connection", Proto: "dnp3", Kind: "malformed"})
	for _, got := range s.Flows(0) {
		if got.Application != "modbus" || got.Identification["binding"] != "observation" {
			t.Fatalf("%+v", got)
		}
	}
}

func TestUtilityEvidenceDoesNotSetApplication(t *testing.T) {
	s := NewStore(4)
	for _, kind := range []string{"ics.verdict", "ics.decision", "ics.session", "identification"} {
		s.Append(Event{FlowID: "flow", Proto: "iec104", Kind: kind})
	}
	if got := s.Flows(0)[0].Application; got != "" {
		t.Fatal(got)
	}
}

func TestFlowEventCountIncludesIdentification(t *testing.T) {
	s := NewStore(4)
	s.Append(Event{FlowID: "flow", Proto: "identify", Kind: "identification"})
	s.Append(Event{FlowID: "flow", Proto: "modbus", Kind: "request"})
	if got := s.Flows(0)[0].EventCount; got != 2 {
		t.Fatalf("flow event count = %d, want 2 including identification", got)
	}
}
