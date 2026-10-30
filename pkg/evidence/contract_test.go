// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func ptr[T any](v T) *T { return &v }

func observation() Observation {
	return Observation{
		SchemaVersion: SchemaVersion, DatasetID: "capture", Source: SourcePCAP,
		CapturedAt:   time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
		ConnectionID: "incarnation-1", ParentID: "parent-1", ObjectCount: 1,
		Service:   ServiceKey{Protocol: "modbus", Coordinates: CoordinatesWire},
		Authority: Authority{Correlation: "wire", RoleCertain: true},
		Quality:   Quality{Complete: true, Decoded: true},
		Modbus:    &Modbus{UnitID: ptr(uint8(0)), FunctionCode: ptr(uint8(3)), Spans: []Span{{First: 0, Last: 1, Role: "read"}}},
		Outcome:   Outcome{Delivery: "unknown"},
		Evidence:  []EvidenceRef{{DatasetID: "capture", ByteOffset: ptr(uint64(0)), PacketFirst: ptr(uint64(1))}},
	}
}

func TestObservationJSONRoundTrip(t *testing.T) {
	for _, protocol := range []string{"modbus", "dnp3", "iec104", "cip"} {
		t.Run(protocol, func(t *testing.T) {
			o := observation()
			o.Service.Protocol = protocol
			if protocol != "modbus" {
				o.Modbus = nil
			}
			switch protocol {
			case "dnp3":
				o.DNP3 = &DNP3{Master: ptr(uint16(0)), FunctionCode: ptr(uint8(1)), Objects: []DNP3Object{{Index: 0, Group: ptr(uint8(1)), Variation: ptr(uint8(2)), Qualifier: ptr(uint8(0)), Spans: []Span{{First: 0, Last: 0, Role: "target"}}}}}
			case "iec104":
				o.IEC104 = &IEC104{APCIType: "I", TypeID: ptr(uint8(45)), Negative: ptr(false), Test: ptr(false), Originator: ptr(uint8(0)), Objects: []IEC104Object{{IOA: ptr(uint32(0)), Select: ptr(false), Qualifier: ptr(uint8(0))}}}
			case "cip":
				o.CIP = &CIP{Service: ptr(uint8(0)), Class: nil, Instance: ptr(uint16(0))}
			}
			if err := o.ValidateEnvelope(); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(o)
			if err != nil {
				t.Fatal(err)
			}
			var got Observation
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(o, got) {
				t.Fatalf("round trip lost selector presence: %s", data)
			}
			if err := got.ValidateEnvelope(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestObservationEnvelopeInvariants(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Observation)
	}{
		{"version", func(o *Observation) { o.SchemaVersion += "-different" }},
		{"union", func(o *Observation) { o.CIP = &CIP{} }},
		{"missing decode", func(o *Observation) { o.Modbus = nil }},
		{"wrong protocol", func(o *Observation) { o.Service.Protocol = "dnp3" }},
		{"pcap NAT invention", func(o *Observation) {
			o.Service.Coordinates = CoordinatesLogical
			o.Authority.Logical = &Tuple{}
			o.Authority.Correlation = "verified"
		}},
		{"unverified logical", func(o *Observation) { o.Source = SourceLive; o.Service.Coordinates = CoordinatesLogical }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := observation()
			tt.change(&o)
			if err := o.ValidateEnvelope(); err == nil {
				t.Fatal("accepted invalid envelope")
			}
		})
	}
	o := observation()
	o.Quality = Quality{Decoded: false, Complete: false, Undecoded: []string{"short_pdu"}}
	o.Modbus = nil
	if err := o.ValidateEnvelope(); err != nil {
		t.Fatalf("must retain undecoded evidence: %v", err)
	}
	o = observation()
	o.Source = SourceLive
	o.Service.Coordinates = CoordinatesLogical
	o.Authority.Logical = &Tuple{}
	o.Authority.Correlation = "verified"
	if err := o.ValidateEnvelope(); err != nil {
		t.Fatal(err)
	}
}

func TestWatchDuration(t *testing.T) {
	for _, seconds := range []int64{0, 1, 3600, 86400, -1, 86401, 1<<63 - 1} {
		t.Run(time.Duration(seconds).String(), func(t *testing.T) {
			d, err := (StartWatchRequest{DurationSeconds: seconds}).Duration()
			if seconds < 0 || seconds > 86400 {
				if err == nil {
					t.Fatal("accepted out-of-budget duration")
				}
				return
			}
			want := time.Duration(seconds) * time.Second
			if seconds == 0 {
				want = time.Hour
			}
			if err != nil || d != want {
				t.Fatalf("got %v, %v; want %v", d, err, want)
			}
		})
	}
}

func TestDatasetWatchJSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	in := struct {
		Dataset Dataset `json:"dataset"`
		Watch   Watch   `json:"watch"`
	}{Dataset: Dataset{SchemaVersion: SchemaVersion, ID: "d1", Source: SourceLive, State: DatasetSealed, CreatedAt: now, SealedAt: &now, ExpiresAt: now.Add(Retention)}, Watch: Watch{ID: "w1", DatasetID: "d1", StartedAt: now.Add(-time.Hour), Deadline: now, StoppedAt: &now, StopReason: "operator"}}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	got := in
	got.Dataset = Dataset{}
	got.Watch = Watch{}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, got) {
		t.Fatalf("dataset/watch changed: %s", data)
	}
}
