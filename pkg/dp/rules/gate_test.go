// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package rules

import (
	"strings"
	"testing"
)

func TestICSDecoderPorts(t *testing.T) {
	for proto, port := range map[string]uint16{"modbus": 502, "cip": 2222, "iec104": 2404, "dnp3": 20000, "CIP": 44818} {
		if !IsICSDecoderPort(proto, port) {
			t.Errorf("%s/%d not a decoder port", proto, port)
		}
	}
	for proto, port := range map[string]uint16{"modbus": 503, "cip": 2404, "iec104": 502, "": 502, "http": 80} {
		if IsICSDecoderPort(proto, port) {
			t.Errorf("%s/%d reported as a decoder port", proto, port)
		}
	}
	if p, ok := ICSDecoderPortIn(500, 600); !ok || p.String() != "modbus/502" {
		t.Fatalf("ICSDecoderPortIn(500, 600) = %v, %v", p, ok)
	}
	if p, ok := ICSDecoderPortIn(1, 65535); !ok || p.Port != 502 {
		t.Fatalf("ICSDecoderPortIn(1, 65535) = %v, %v", p, ok)
	}
	if p, ok := ICSDecoderPortIn(44818, 44818); !ok || p.String() != "cip/44818" {
		t.Fatalf("ICSDecoderPortIn(44818, 44818) = %v, %v", p, ok)
	}
	if _, ok := ICSDecoderPortIn(503, 2221); ok {
		t.Fatal("503-2221 reported a decoder port")
	}
}

func TestGateSelectionValidate(t *testing.T) {
	ok := GateSelection{Enabled: true,
		Include: []GateEntry{{DestZones: []string{"wan"}, Ports: []GatePortRange{{Lo: 80, Hi: 80}, {Lo: 503, Hi: 2221}}}},
		Exclude: []GateEntry{{Ports: []GatePortRange{{Lo: 502, Hi: 502}}}},
		Zones:   []GateZone{{Name: "wan", Index: 1}, {Name: "dmz", Index: 2}},
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid selection rejected: %v", err)
	}
	if err := (GateSelection{}).Validate(); err != nil {
		t.Fatalf("empty selection rejected: %v", err)
	}
	for name, tc := range map[string]struct {
		gate GateSelection
		err  string
	}{
		"decoder port": {GateSelection{Include: []GateEntry{{Ports: []GatePortRange{{Lo: 80, Hi: 80}, {Lo: 500, Hi: 600}}}}}, "gate include[0]: ports 500-600 cover ICS decoder port modbus/502"},
		"reversed":     {GateSelection{Include: []GateEntry{{Ports: []GatePortRange{{Lo: 90, Hi: 80}}}}}, "reversed port range 90-80"},
		"zero index":   {GateSelection{Zones: []GateZone{{Name: "wan"}}}, `zone "wan" has index 0`},
		"shared index": {GateSelection{Zones: []GateZone{{Name: "wan", Index: 7}, {Name: "dmz", Index: 7}}}, `zones "wan" and "dmz" share index 7`},
	} {
		if err := tc.gate.Validate(); err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%s: Validate = %v, want %q", name, err, tc.err)
		}
	}
}
