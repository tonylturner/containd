// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package anomaly

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestIEC104RoleViolations(t *testing.T) {
	cases := []struct {
		attrs map[string]any
		want  bool
	}{
		{map[string]any{"direction": "request", "type_id": uint8(3), "class": "monitor"}, true},
		{map[string]any{"direction": "response", "type_id": uint8(46), "class": "control", "cause": uint8(6)}, true},
		{map[string]any{"direction": "response", "type_id": float64(100), "class": "system", "cause": float64(8)}, true},
		{map[string]any{"direction": "response", "type_id": uint8(46), "class": "control", "cause": uint8(7)}, false}, // confirmation
		{map[string]any{"direction": "response", "type_id": uint8(3), "class": "monitor", "cause": uint8(3)}, false},  // spontaneous
		{map[string]any{"direction": "request", "type_id": uint8(46), "class": "control", "cause": uint8(6)}, false},
		{map[string]any{"direction": "request"}, false},
	}
	for _, c := range cases {
		if got := IEC104RoleViolation(c.attrs); got != c.want {
			t.Fatalf("%v: role violation = %v, want %v", c.attrs, got, c.want)
		}
		got := New().Check("10.0.0.1", "10.0.0.2", dpi.Event{Proto: "iec104", Kind: "malformed", Attributes: c.attrs})
		found := false
		for _, a := range got {
			found = found || (a.Protocol == "iec104" && a.Type == "protocol_violation")
		}
		if found != c.want {
			t.Fatalf("%v: anomalies = %+v", c.attrs, got)
		}
	}
}

func TestIEC104RateCountsAPDUsOnce(t *testing.T) {
	d := New(WithTotalRateThreshold(2), WithWriteRateThreshold(1000))
	// One GI response APDU with five objects is one operation.
	for i := 0; i < 5; i++ {
		ev := dpi.Event{Proto: "iec104", Kind: "response", Attributes: map[string]any{"apdu_id": "s-1/s/0", "type_id": uint8(3)}}
		for _, a := range d.Check("10.0.0.2", "10.0.0.1", ev) {
			if a.Type == "rate_anomaly" {
				t.Fatalf("object %d of one APDU raised a rate anomaly", i)
			}
		}
	}
	rate := 0
	for i := 0; i < 3; i++ {
		ev := dpi.Event{Proto: "iec104", Kind: "response", Attributes: map[string]any{"apdu_id": "s-1/s/" + string(rune('a'+i))}}
		for _, a := range d.Check("10.0.0.2", "10.0.0.1", ev) {
			if a.Type == "rate_anomaly" {
				rate++
			}
		}
	}
	// Four APDUs in all: the third and fourth exceed the threshold of 2.
	// Counted per object it would be eight operations and six anomalies.
	if rate != 2 {
		t.Fatalf("rate anomalies = %d, want 2", rate)
	}
}
