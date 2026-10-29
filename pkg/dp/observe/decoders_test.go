// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"encoding/binary"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/cip"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/identify"
)

func allDecoders() []dpi.StreamDecoder {
	return []dpi.StreamDecoder{modbus.NewDecoder(), dnp3.NewDecoder(), iec104.NewDecoder(), cip.NewDecoder()}
}
func realObserver(t *testing.T, change func(*Options)) *Observer {
	t.Helper()
	m, err := dpi.NewObservationManager(allDecoders()...)
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{Budgets: identify.DefaultBudgets(), Markers: 32, Now: func() time.Time { return instant }, Manager: m}
	if change != nil {
		change(&opts)
	}
	o, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return o
}
func encapsulation(command uint16, session uint32, body []byte) []byte {
	b := make([]byte, 24+len(body))
	binary.LittleEndian.PutUint16(b, command)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(body)))
	binary.LittleEndian.PutUint32(b[4:], session)
	copy(b[24:], body)
	return b
}
func listReply() []byte {
	return encapsulation(4, 0, append([]byte{1, 0, 0, 1, 20, 0, 1, 0}, make([]byte, 18)...))
}
func dnpLink() []byte {
	b := []byte{5, 0x64, 8, 0xc4, 1, 0, 2, 0}
	b = withCRC(b)
	return append(b, withCRC([]byte{0xc0, 0xc0, 1})...)
}

func withCRC(b []byte) []byte {
	var crc uint16
	for _, v := range b {
		crc ^= uint16(v)
		for range 8 {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xa6bc
			} else {
				crc >>= 1
			}
		}
	}
	return append(b, byte(^crc), byte(^crc>>8))
}
func semantic(events []dpi.Event) []any {
	var out []any
	for _, e := range events {
		attrs := map[string]any{}
		for k, v := range e.Attributes {
			switch k {
			case eventfields.KeyObservationOnly, eventfields.KeyBindingSource, eventfields.KeyAPDUID, eventfields.KeySessionID, "stream_session":
				continue
			}
			attrs[k] = v
		}
		// Normalize numeric wire types through the real JSON representation.
		b, _ := json.Marshal(map[string]any{"proto": e.Proto, "kind": e.Kind, "attrs": attrs})
		var item any
		_ = json.Unmarshal(b, &item)
		out = append(out, item)
	}
	return out
}

func TestRealDecoderParity(t *testing.T) {
	for _, f := range []struct {
		protocol       identify.Protocol
		port           uint16
		request, reply []byte
	}{
		{identify.Modbus, 502, request, reply},
		{identify.IEC104, 2404, []byte{0x68, 4, 7, 0, 0, 0}, []byte{0x68, 4, 11, 0, 0, 0}},
		{identify.ENIP, 44818, encapsulation(0x65, 0, []byte{1, 0, 0, 0}), encapsulation(0x65, 42, []byte{1, 0, 0, 0})},
		{identify.DNP3, 20000, dnpLink(), nil},
	} {
		t.Run(string(f.protocol), func(t *testing.T) {
			o := realObserver(t, nil)
			s := states(f.port, 6)
			o.Open("run/1", identify.Meta{Transport: 6, Ports: [2]uint16{50000, f.port}})
			o.Observe("run/1", Packet{Arrival: identify.Arrival{SYN: true, Sequence: 99}, State: s[0]})
			o.Observe("run/1", Packet{Arrival: identify.Arrival{Direction: 1, SYN: true, Sequence: 199}, SYNACK: true, State: s[1]})
			var got Output
			got.append(payload(o, "run/1", s, 0, 100, f.request))
			if len(f.reply) > 0 {
				got.append(payload(o, "run/1", s, 1, 200, f.reply))
			}
			if len(got.Identifications) != 1 || got.Identifications[0].Decision.Protocol != f.protocol {
				t.Fatal(got)
			}
			legacyDecs := allDecoders()
			legacy := dpi.NewManager(legacyDecs[0], legacyDecs[1], legacyDecs[2], legacyDecs[3])
			var want, actual []dpi.Event
			for dir, data := range [][]byte{f.request, f.reply} {
				if len(data) == 0 {
					continue
				}
				streamDir := dpi.ClientToServer
				if dir == 1 {
					streamDir = dpi.ServerToClient
				}
				r := legacy.Inspect(s[dir], &dpi.ParsedPacket{Proto: "tcp", Payload: data, HasOffset: true, Session: "legacy", Dir: streamDir})
				if r.Err != nil {
					t.Fatal(r.Err)
				}
				want = append(want, r.Events...)
			}
			for _, b := range got.Batches {
				if b.Err != nil {
					t.Fatal(b.Err)
				}
				actual = append(actual, b.Events...)
			}
			if len(actual) == 0 || !reflect.DeepEqual(semantic(actual), semantic(want)) {
				t.Fatalf("observation=%v legacy=%v", semantic(actual), semantic(want))
			}
		})
	}
}

func TestUDP2222BindsEncapsulation(t *testing.T) {
	o := realObserver(t, nil)
	s := states(2222, 17)
	o.Open("udp/1", identify.Meta{Transport: 17, Ports: [2]uint16{50000, 2222}})
	payload(o, "udp/1", s, 0, 0, encapsulation(4, 0, nil))
	out := payload(o, "udp/1", s, 1, 0, listReply())
	if len(out.Identifications) != 1 || out.Identifications[0].Decision.Protocol != identify.ENIP || out.Identifications[0].Decision.Expected != [2]identify.Protocol{} {
		t.Fatal(out)
	}
	events := 0
	for _, b := range out.Batches {
		if b.Err != nil {
			t.Fatal(b.Err)
		}
		for _, e := range b.Events {
			events++
			if _, ok := e.Attributes["enip_command"]; !ok {
				t.Fatal("implicit I/O selected", e)
			}
		}
	}
	if events != 2 {
		t.Fatal(events)
	}
	// A continuation is also encapsulation, never implicit I/O by its port.
	out = payload(o, "udp/1", s, 0, 0, encapsulation(4, 0, nil))
	if len(out.Batches) != 1 || out.Batches[0].Events[0].Attributes["enip_command"] == nil {
		t.Fatal(out)
	}
}

func TestClippedUDPDoesNotBind(t *testing.T) {
	o := realObserver(t, func(opts *Options) { opts.Budgets.BytesPerDirection = 24 })
	s := states(2222, 17)
	o.Open("u", identify.Meta{Transport: 17, Ports: [2]uint16{50000, 2222}})
	out := payload(o, "u", s, 0, 0, listReply())
	if len(out.Identifications) != 1 || out.Identifications[0].Binding != None || out.Identifications[0].Decision.Coverage != identify.Budget || len(out.Batches) != 0 {
		t.Fatal(out)
	}
}

func TestBoundProtocolConflict(t *testing.T) {
	o := realObserver(t, nil)
	s := openTCP(t, o, "modbus")
	payload(o, "modbus", s, 0, 100, request)
	payload(o, "modbus", s, 1, 200, reply)
	s = openTCP(t, o, "iec")
	payload(o, "iec", s, 0, 100, []byte{0x68, 4, 7, 0, 0, 0})
	payload(o, "iec", s, 1, 200, []byte{0x68, 4, 11, 0, 0, 0})
	if o.Counters().Bindings != 2 {
		t.Fatal(o.Counters())
	}
	out := o.Adopt("modbus", "iec", identify.Remap{0, 1})
	if len(out.Identifications) != 0 || o.Counters().Bindings != 0 || o.Counters().AdoptionConflicts != 1 || o.Counters().Markers != 1 {
		t.Fatal(out, o.Counters())
	}
}

func TestAmbiguityAtEOFAndLaterConfirmation(t *testing.T) {
	for _, finish := range []bool{false, true} {
		o := realObserver(t, nil)
		s := openTCP(t, o, "k")
		poly := make([]byte, 24)
		poly[0], poly[5], poly[6], poly[7] = 0x66, 2, 1, 100
		poly[13], poly[14], poly[15] = 10, 1, 100
		if out := payload(o, "k", s, 0, 100, poly); len(out.Identifications) != 0 {
			t.Fatal(out)
		}
		var out Output
		if finish {
			out = o.Finish("k")
		} else {
			out = payload(o, "k", s, 0, 124, listReply())
		}
		if len(out.Identifications) != 1 {
			t.Fatal(out)
		}
		d := out.Identifications[0]
		if finish {
			if d.Decision.State != identify.Incomplete || d.Binding != None || d.Decision.Results[0].State != identify.Candidate || d.Decision.Results[3].State != identify.Candidate {
				t.Fatal(d)
			}
		} else if d.Decision.State != identify.Confirmed || d.Binding != Observation {
			t.Fatal(d)
		}
	}
}

func TestIdentificationJSONContract(t *testing.T) {
	o := realObserver(t, func(opts *Options) { opts.Scope = func(identify.Key, identify.Protocol) any { return true } })
	s := openTCP(t, o, "k")
	payload(o, "k", s, 0, 100, request)
	out := payload(o, "k", s, 1, 200, reply)
	e := out.Identifications[0].Event
	if e.Proto != "identify" || e.Kind != "identification" {
		t.Fatal(e)
	}
	data, err := json.Marshal(e.Attributes)
	if err != nil {
		t.Fatal(err)
	}
	var attrs map[string]any
	if err = json.Unmarshal(data, &attrs); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"protocol", "identification_state", "reason", "expected", "service_transport", "service_port", "mismatch", "binding", "outside_rule_port_scope", "profile_version", "syn_coverage", "identification_candidates", "identification_coverage"} {
		if _, ok := attrs[k]; !ok {
			t.Fatal("missing frozen key", k)
		}
	}
	if attrs["outside_rule_port_scope"] != true || attrs["binding"] != "observation" || attrs["protocol"] != "modbus" || attrs["service_port"] != float64(1502) {
		t.Fatal(attrs)
	}
}

func TestStandardPortMismatchIsCallerChoice(t *testing.T) {
	for _, suppress := range []bool{false, true} {
		o := realObserver(t, func(opts *Options) {
			opts.LegacyDecodes = func(_ identify.Key, p identify.Protocol) bool { return suppress && p == identify.Modbus }
		})
		s := states(2404, 6)
		o.Open("k", identify.Meta{Transport: 6, Ports: [2]uint16{50000, 2404}})
		o.Observe("k", Packet{Arrival: identify.Arrival{SYN: true, Sequence: 99}, State: s[0]})
		o.Observe("k", Packet{Arrival: identify.Arrival{Direction: 1, SYN: true, Sequence: 199}, SYNACK: true, State: s[1]})
		payload(o, "k", s, 0, 100, request)
		out := payload(o, "k", s, 1, 200, reply)
		if len(out.Identifications) != 1 || out.Identifications[0].Event.Attributes[eventfields.KeyMismatch] != true {
			t.Fatal(out)
		}
		if suppress && len(out.Batches) != 0 || !suppress && len(out.Batches) == 0 {
			t.Fatal(out)
		}
	}
}

func TestUDPAdoptionPreservesCaptureAttribution(t *testing.T) {
	o := realObserver(t, nil)
	s := states(2222, 17)
	for _, key := range []identify.Key{"from", "to"} {
		o.Open(key, identify.Meta{Transport: 17, Ports: [2]uint16{50000, 2222}})
	}
	payload(o, "from", s, 0, 0, encapsulation(4, 0, nil))
	payload(o, "to", s, 1, 0, encapsulation(4, 0, nil))
	o.Adopt("from", "to", identify.Remap{0, 1})
	out := payload(o, "to", s, 1, 0, listReply())
	if len(out.Identifications) != 1 || len(out.Batches) != 3 {
		t.Fatal(out)
	}
	for i, wantDir := range []uint8{0, 1, 1} {
		b := out.Batches[i]
		if b.Dir != wantDir || b.State != s[wantDir] || b.At != instant.Add(time.Duration(wantDir)*time.Second) || b.Err != nil {
			t.Fatal(i, b)
		}
	}
}
