// SPDX-License-Identifier: Apache-2.0

package project

import (
	"encoding/json"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestPairingClassSchemaProjection(t *testing.T) {
	tests := []struct {
		name, proto, kind string
		attrs             map[string]any
		want              rules.MessageClass
	}{
		{"modbusRequest", "modbus", "request", nil, rules.ClassRequest},
		{"modbusResponse", "modbus", "response", nil, rules.ClassSolicited},
		{"modbusException", "modbus", "exception", nil, rules.ClassSolicited},
		{"cipUnchanged", "cip", "response", nil, rules.ClassUnknown},
		{"missingFacts", "dnp3", "response", nil, rules.ClassUnknown},
		{"dnp3Link", "dnp3", "session", nil, rules.ClassSession},
		{"dnp3Confirm", "dnp3", "request", map[string]any{"function_code": 0}, rules.ClassSession},
		{"dnp3Read", "dnp3", "request", map[string]any{"function_code": 1, "application_uns": false}, rules.ClassRequest},
		{"dnp3Enable", "dnp3", "request", map[string]any{"function_code": 20, "application_uns": false}, rules.ClassRequest},
		{"dnp3Disable", "dnp3", "request", map[string]any{"function_code": 21, "application_uns": false}, rules.ClassRequest},
		{"dnp3Response", "dnp3", "response", map[string]any{"function_code": 129, "application_uns": false}, rules.ClassSolicited},
		{"dnp3Unsolicited", "dnp3", "response", map[string]any{"function_code": 130, "application_uns": true}, rules.ClassAutonomous},
		{"dnp3MissingUNS", "dnp3", "response", map[string]any{"function_code": 130}, rules.ClassUnknown},
		{"dnp3FalseUNS", "dnp3", "response", map[string]any{"function_code": 130, "application_uns": false}, rules.ClassUnknown},
		{"dnp3WrongFC", "dnp3", "response", map[string]any{"function_code": 129, "application_uns": true}, rules.ClassUnknown},
		{"dnp3UnknownFC", "dnp3", "request", map[string]any{"function_code": 128, "application_uns": false}, rules.ClassUnknown},
		{"dnp3Malformed", "dnp3", "malformed", map[string]any{"function_code": 130, "application_uns": true}, rules.ClassUnknown},
		{"noStampAuthority", "dnp3", "response", map[string]any{"message_class": "autonomous", "pairing_outcome": "paired"}, rules.ClassUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := dpi.Event{Proto: tc.proto, Kind: tc.kind, Attributes: tc.attrs}
			assertClassProjection(t, ev, tc.want)
		})
	}
	t.Run("iecTables", func(t *testing.T) {
		for _, apci := range []string{"S", "U"} {
			assertClassProjection(t, dpi.Event{Proto: "iec104", Kind: "apci", Attributes: map[string]any{"apci_type": apci}}, rules.ClassSession)
		}
		for _, tc := range []struct {
			id, cot int
			dir     string
			want    rules.MessageClass
		}{
			{45, 6, "request", rules.ClassRequest},
			{45, 7, "response", rules.ClassSolicited},
			{45, 10, "response", rules.ClassSolicited},
			{1, 20, "response", rules.ClassSolicited},
			{1, 36, "response", rules.ClassSolicited},
			{1, 5, "response", rules.ClassSolicited},
			{1, 1, "response", rules.ClassAutonomous},
			{30, 2, "response", rules.ClassAutonomous},
			{30, 3, "response", rules.ClassAutonomous},
			{70, 4, "response", rules.ClassAutonomous},
			{70, 3, "response", rules.ClassUnknown},
			{1, 4, "response", rules.ClassUnknown},
			{45, 3, "response", rules.ClassUnknown},
			{104, 3, "response", rules.ClassUnknown},
			{1, 3, "request", rules.ClassUnknown},
			{1, 3, "", rules.ClassUnknown},
		} {
			attrs := map[string]any{eventfields.KeyAPCIType: "I", eventfields.KeyTypeID: tc.id, eventfields.KeyCause: tc.cot, eventfields.KeyDirection: tc.dir}
			assertClassProjection(t, dpi.Event{Proto: "iec104", Kind: tc.dir, Attributes: attrs}, tc.want)
		}
	})
}

func assertClassProjection(t *testing.T, ev dpi.Event, want rules.MessageClass) {
	t.Helper()
	if got := MessageClass(ev); got != want {
		t.Fatalf("%+v: class=%s, want %s", ev, got, want)
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var retained dpi.Event
	if err := json.Unmarshal(raw, &retained); err != nil {
		t.Fatal(err)
	}
	if got := MessageClass(retained); got != want {
		t.Fatalf("retained %s: class=%s, want %s", raw, got, want)
	}
}
