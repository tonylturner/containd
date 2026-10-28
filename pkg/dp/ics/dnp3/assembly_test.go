// SPDX-License-Identifier: Apache-2.0
package dnp3

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

func parseAssembly(t *testing.T, d *Decoder, session string, dir dpi.StreamDir, wire []byte) []dpi.Event {
	t.Helper()
	res, err := d.ParseStream(dnp3State(), dpi.StreamView{Session: session, Dir: dir, Bytes: wire})
	total := 0
	for k, c := range d.stations {
		total += contextBytes(k, c)
	}
	if total != d.retained || total > maxRetainedBytes {
		t.Fatalf("state accounting %d != %d", total, d.retained)
	}
	if err != nil || res.Consumed != len(wire) {
		t.Fatalf("%+v %v", res, err)
	}
	var events []dpi.Event
	for _, f := range res.Frames {
		events = append(events, f.Events...)
	}
	return events
}
func hasCode(t *testing.T, ev dpi.Event, key, code string) {
	t.Helper()
	codes, _ := eventfields.Strings(ev.Attributes, key)
	for _, c := range codes {
		if c == code {
			return
		}
	}
	t.Fatalf("missing %s in %+v", code, ev.Attributes)
}
func expectOne(t *testing.T, events []dpi.Event) dpi.Event {
	t.Helper()
	if len(events) != 1 {
		t.Fatalf("want one event, got %+v", events)
	}
	return events[0]
}
func TestDNP3TransportAssembly(t *testing.T) {
	// Transport splits application header, index and a CROB's multi-byte values.
	app := []byte{0xc3, FuncOperate, 12, 1, 0x28, 2, 0, 0x34, 0x12, 0x81, 2, 0x78, 0x56, 0x34, 0x12, 4, 3, 2, 1, 0, 0x35, 0x12, 3, 1, 100, 0, 0, 0, 200, 0, 0, 0, 1}
	var wire []byte
	chunks := [][]byte{app[:1], app[1:8], app[8:13], app[13:]}
	for i, b := range chunks {
		h := byte((62 + i) & 63)
		if i == 0 {
			h |= TransportFIR
		}
		if i == len(chunks)-1 {
			h |= TransportFIN
		}
		wire = append(wire, linkFrame(0xc4, append([]byte{h}, b...))...)
	}
	decodertest.CheckSplitsFactory(t, func() dpi.StreamDecoder { return NewDecoder() }, dnp3State(), dpi.StreamView{Session: "assembly", Dir: dpi.ClientToServer, Base: 11, Bytes: wire})
	d := NewDecoder()
	res, err := d.ParseStream(dnp3State(), dpi.StreamView{Session: "assembly", Base: 11, Bytes: wire})
	if err != nil || len(res.Frames) != 4 {
		t.Fatal(res, err)
	}
	for _, f := range res.Frames[:3] {
		if len(f.Events) != 0 {
			t.Fatal("early semantic event", f)
		}
	}
	ev := expectOne(t, res.Frames[3].Events)
	hs := ev.Attributes["objects"].([]ObjectHeader)
	if len(hs) != 1 || len(hs[0].Points) != 2 {
		t.Fatal(hs)
	}
	p := hs[0].Points[0]
	v := p.CROB
	if *p.Index != 0x1234 || v.Control != 0x81 || v.OperationName != "pulse_on" || v.TripClose != 2 || v.Count != 2 || v.OnTime != 0x12345678 || v.OffTime != 0x01020304 || v.Status != 0 {
		t.Fatal(p, v)
	}
	if *hs[0].Points[1].Index != 0x1235 || hs[0].Points[1].CROB.Status != 1 {
		t.Fatal(hs)
	}
	ranges := ev.Attributes["link_ranges"].([]LinkRange)
	if len(ranges) != 4 || ranges[0].Start != 11 || ranges[3].End != 11+int64(len(wire)) {
		t.Fatal(ranges)
	}
	if ev.Attributes["raw_hex"] != hexOf(wire[ranges[3].Start-11:]) {
		t.Fatal("logical bytes mislabelled raw")
	}

}
func TestDNP3TransportAssemblyFailures(t *testing.T) {
	first := linkFrame(0x44, []byte{0x7f, 0xc0, FuncResponse, 0, 0})
	for _, tc := range []struct {
		name string
		tail []byte
		code string
	}{
		{"orphan", linkFrame(0x44, []byte{0x80, 1}), "dnp3.transport_orphan"},
		{"gap", concat(first, linkFrame(0x44, []byte{0x81, 1})), "dnp3.transport_sequence"},
		{"conflict", concat(first, linkFrame(0x44, []byte{0xbf, 9})), "dnp3.transport_conflict"},
		{"duplicate", concat(first, first), "dnp3.transport_duplicate"},
		{"restart", concat(first, linkFrame(0x44, []byte{0xc0, 0xc0, FuncResponse, 0, 0})), "dnp3.transport_restart"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := expectOne(t, parseAssembly(t, NewDecoder(), "s", dpi.ServerToClient, tc.tail))
			hasCode(t, ev, eventfields.KeyConformance, tc.code)
		})
	}
	// An identical continuation is ignored, but the later completion still decodes.
	d := NewDecoder()
	parseAssembly(t, d, "s", dpi.ServerToClient, first)
	parseAssembly(t, d, "s", dpi.ServerToClient, linkFrame(0x44, []byte{0, 1, 2, 0, 0}))
	events := parseAssembly(t, d, "s", dpi.ServerToClient, concat(linkFrame(0x44, []byte{0, 1, 2, 0, 0}), linkFrame(0x44, []byte{0x81, 0, 0x81})))
	if len(events) != 2 || events[1].Kind != "response" {
		t.Fatal(events)
	}
	hasCode(t, events[0], eventfields.KeyConformance, "dnp3.transport_duplicate")
}
func TestDNP3TransportAssemblyIsolationAndExpiry(t *testing.T) {
	now := time.Unix(100, 0)
	d := NewDecoderWithClock(func() time.Time { return now })
	first := linkFrame(0x44, []byte{0x40, 0xc0, FuncResponse, 0, 0})
	last := linkFrame(0x44, []byte{0x81})
	for _, s := range []string{"one", "two"} {
		parseAssembly(t, d, s, dpi.ServerToClient, first)
	}
	expectOne(t, parseAssembly(t, d, "one", dpi.ClientToServer, last))
	d.StreamEnded("one", dpi.ServerToClient)
	hasCode(t, expectOne(t, parseAssembly(t, d, "one", dpi.ServerToClient, last)), eventfields.KeyConformance, "dnp3.transport_orphan")
	ev := expectOne(t, parseAssembly(t, d, "two", dpi.ServerToClient, last))
	if ev.Kind != "response" {
		t.Fatal(ev)
	}
	parseAssembly(t, d, "expiry", dpi.ServerToClient, first)
	now = now.Add(assemblyIdle)
	hasCode(t, expectOne(t, parseAssembly(t, d, "expiry", dpi.ServerToClient, last)), eventfields.KeyConformance, "dnp3.transport_orphan")
	// Absolute lifetime expires even with activity inside the idle window.
	parseAssembly(t, d, "life", dpi.ServerToClient, first)
	for i := 1; i <= 3; i++ {
		now = now.Add(20 * time.Second)
		events := parseAssembly(t, d, "life", dpi.ServerToClient, linkFrame(0x44, []byte{byte(i)}))
		if i == 3 {
			hasCode(t, expectOne(t, events), eventfields.KeyConformance, "dnp3.transport_orphan")
		} else if len(events) != 0 {
			t.Fatal(events)
		}
	}
	// Interleaved ordered station pairs never share bytes.
	d = NewDecoder()
	parseAssembly(t, d, "s", dpi.ServerToClient, first)
	other := buildTestFrame(6, 0x44, 7, 8, []byte{0x81})
	hasCode(t, expectOne(t, parseAssembly(t, d, "s", dpi.ServerToClient, other)), eventfields.KeyConformance, "dnp3.transport_orphan")
	if expectOne(t, parseAssembly(t, d, "s", dpi.ServerToClient, last)).Kind != "response" {
		t.Fatal("station cross-talk")
	}
	d.StreamEnded("s", dpi.ServerToClient)
	if d.retained != 0 || len(d.stations) != 0 {
		t.Fatal("leaked state", d.retained)
	}
}
func TestDNP3TransportAssemblyBounds(t *testing.T) {
	t.Run("bytes", func(t *testing.T) {
		d := NewDecoder()
		var events []dpi.Event
		for i := 0; i <= maxAssemblyBytes/249; i++ {
			h := byte(i & 63)
			if i == 0 {
				h |= TransportFIR
			}
			events = parseAssembly(t, d, "s", dpi.ServerToClient, linkFrame(0x44, append([]byte{h}, bytes.Repeat([]byte{0}, 249)...)))
		}
		hasCode(t, expectOne(t, events), eventfields.KeyUndecoded, "dnp3.assembly_limit")
	})
	t.Run("segments", func(t *testing.T) {
		d := NewDecoder()
		var events []dpi.Event
		for i := 0; i <= maxAssemblySegments; i++ {
			h := byte(i & 63)
			if i == 0 {
				h |= TransportFIR
			}
			events = parseAssembly(t, d, "s", dpi.ServerToClient, linkFrame(0x44, []byte{h}))
		}
		hasCode(t, expectOne(t, events), eventfields.KeyUndecoded, "dnp3.assembly_limit")
	})
	t.Run("contexts", func(t *testing.T) {
		d := NewDecoder()
		for i := 0; i < maxStationContexts; i++ {
			parseAssembly(t, d, fmt.Sprint(i), dpi.ServerToClient, linkFrame(0x44, []byte{0x40}))
		}
		hasCode(t, expectOne(t, parseAssembly(t, d, "extra", dpi.ServerToClient, linkFrame(0x44, []byte{0x40}))), eventfields.KeyUndecoded, "dnp3.assembly_budget")
		if len(d.stations) != maxStationContexts || d.retained > maxRetainedBytes {
			t.Fatal("unbounded state")
		}
	})
}
func TestDNP3ApplicationAssembly(t *testing.T) {
	d := NewDecoder()
	response := func(h, fc byte) []byte { return linkFrame(0x44, []byte{0xc0, h, fc, 0, 0, 1, 2, 0, 4, 4, 0x81}) }
	for i, h := range []byte{0xae, 0x2f, 0x60} {
		ev := expectOne(t, parseAssembly(t, d, "s", dpi.ServerToClient, response(h, FuncResponse)))
		if ev.Attributes["application_fragment"] != i+1 || ev.Attributes["application_complete"] != (i == 2) {
			t.Fatal(ev.Attributes)
		}
		if _, ok := ev.Attributes[eventfields.KeyUndecoded]; ok {
			t.Fatal(ev.Attributes)
		}
	}
	// Solicited and unsolicited responses progress independently, with 15->0 wrap.
	d = NewDecoder()
	parseAssembly(t, d, "s", dpi.ServerToClient, response(0x8f, FuncResponse))
	parseAssembly(t, d, "s", dpi.ServerToClient, response(0x9a, FuncUnsolicitedResponse))
	ev := expectOne(t, parseAssembly(t, d, "s", dpi.ServerToClient, response(0x40, FuncResponse)))
	if ev.Attributes["application_complete"] != true {
		t.Fatal(ev)
	}
	ev = expectOne(t, parseAssembly(t, d, "s", dpi.ServerToClient, response(0x5b, FuncUnsolicitedResponse)))
	if ev.Attributes["application_complete"] != true {
		t.Fatal(ev)
	}
	ev = expectOne(t, parseAssembly(t, d, "s", dpi.ServerToClient, response(0x42, FuncResponse)))
	hasCode(t, ev, eventfields.KeyUndecoded, "dnp3.application_incomplete")
	// CON is tracked against the reverse ordered station pair, same session/UNS.
	reply := buildTestFrame(10, 0x44, 1, 10, []byte{0xc0, 0xf3, FuncUnsolicitedResponse, 0, 0})
	parseAssembly(t, d, "confirm", dpi.ServerToClient, reply)
	confirm := buildTestFrame(8, 0xc4, 10, 1, []byte{0xc0, 0xd3, FuncConfirm})
	ev = expectOne(t, parseAssembly(t, d, "confirm", dpi.ClientToServer, confirm))
	if ev.Attributes["confirmation_matched"] != true {
		t.Fatal(ev)
	}
	ev = expectOne(t, parseAssembly(t, d, "confirm", dpi.ClientToServer, confirm))
	if ev.Attributes["confirmation_matched"] != false {
		t.Fatal("confirmation reused")
	}
}
func TestDNP3PointEvidence(t *testing.T) {
	for _, width := range []int{1, 2, 4} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			rc := byte(0)
			if width == 2 {
				rc = 1
			}
			if width == 4 {
				rc = 2
			}
			b := []byte{30, 1, rc}
			for _, v := range []byte{3, 4} {
				b = append(b, v)
				b = append(b, make([]byte, width-1)...)
			}
			hs, stop := parseObjectHeaders(b, 0, FuncRead)
			if stop != walkComplete || *hs[0].Start != 3 || *hs[0].Stop != 4 || hs[0].Count != 2 {
				t.Fatal(hs, stop)
			}
			prefix := byte(1)
			if width == 2 {
				prefix = 2
			}
			if width == 4 {
				prefix = 3
			}
			b = []byte{30, 1, prefix<<4 | 7, 2}
			for _, v := range []byte{7, 9} {
				b = append(b, v)
				b = append(b, make([]byte, width-1)...)
			}
			hs, stop = parseObjectHeaders(b, 0, FuncRead)
			if stop != walkComplete || *hs[0].Points[0].Index != 7 || *hs[0].Points[1].Index != 9 {
				t.Fatal(hs, stop)
			}
		})
	}
	hs, stop := parseObjectHeaders([]byte{1, 2, 0, 7, 8, 0x81}, 0, FuncResponse)
	if stop != walkTruncated || len(hs[0].Points) != 1 || *hs[0].Points[0].Index != 7 {
		t.Fatal("lost complete prefix", hs, stop)
	}
	hs, stop = parseObjectHeaders([]byte{1, 2, 2, 0, 0, 0, 0, 255, 255, 255, 255}, 0, FuncRead)
	if stop != walkComplete || hs[0].Count != uint64(1)<<32 {
		t.Fatal("32-bit range count overflow", hs, stop)
	}
	// A compact read range does not allocate a point record per requested index.
	hs, stop = parseObjectHeaders([]byte{1, 2, 2, 0, 0, 0, 0, 254, 255, 255, 255}, 0, FuncRead)
	if stop != walkComplete || len(hs[0].Points) != 0 || hs[0].Count != uint64(^uint32(0)) {
		t.Fatal(hs, stop)
	}
	// Serialized evidence preserves index absence rather than inventing index zero.
	ev := expectOne(t, parseAssembly(t, NewDecoder(), "s", dpi.ClientToServer, appFrame(0, FuncOperate, 12, 1, 7, 1, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0)))
	for _, attrs := range decodertest.Forms(t, ev.Attributes) {
		encoded, err := json.Marshal(attrs["objects"])
		if err != nil || bytes.Contains(encoded, []byte(`"index"`)) || !bytes.Contains(encoded, []byte(`"crob"`)) {
			t.Fatalf("evidence %s: %v", encoded, err)
		}
	}
}

func TestDNP3TransportAssemblyLinkRetryAndCRC(t *testing.T) {
	first := linkFrame(0x53, []byte{0x40, 0xc0, FuncResponse, 0, 0}) // confirmed data, FCV, FCB=0
	last := linkFrame(0x73, []byte{0x81})                            // toggled FCB
	d := NewDecoder()
	parseAssembly(t, d, "s", dpi.ServerToClient, first)
	hasCode(t, expectOne(t, parseAssembly(t, d, "s", dpi.ServerToClient, first)), eventfields.KeyConformance, "dnp3.link_duplicate")
	if expectOne(t, parseAssembly(t, d, "s", dpi.ServerToClient, last)).Kind != "response" {
		t.Fatal("lost response after link retry")
	}
	d = NewDecoder()
	parseAssembly(t, d, "s", dpi.ServerToClient, first)
	hasCode(t, expectOne(t, parseAssembly(t, d, "s", dpi.ServerToClient, linkFrame(0x53, []byte{0x40, 0xc1, FuncResponse, 0, 0}))), eventfields.KeyConformance, "dnp3.link_retry_conflict")
	hasCode(t, expectOne(t, parseAssembly(t, d, "s", dpi.ServerToClient, last)), eventfields.KeyConformance, "dnp3.transport_orphan")
	d = NewDecoder()
	parseAssembly(t, d, "s", dpi.ServerToClient, first)
	parseAssembly(t, d, "s", dpi.ServerToClient, linkFrame(0x40, nil)) // reset-link-states
	hasCode(t, expectOne(t, parseAssembly(t, d, "s", dpi.ServerToClient, last)), eventfields.KeyConformance, "dnp3.transport_orphan")
	// A data CRC on a nonfinal segment is visible there and accumulated on FIN.
	bad := copyBytes(first)
	bad[len(bad)-1] ^= 1
	d = NewDecoder()
	hasCode(t, expectOne(t, parseAssembly(t, d, "s", dpi.ServerToClient, bad)), eventfields.KeyConformance, "dnp3.data_crc")
	hasCode(t, expectOne(t, parseAssembly(t, d, "s", dpi.ServerToClient, last)), eventfields.KeyConformance, "dnp3.data_crc")
	// Unconfirmed identical complete transactions are not link duplicates.
	d = NewDecoder()
	events := parseAssembly(t, d, "s", dpi.ClientToServer, concat(readFrame, readFrame))
	if len(events) != 2 || events[0].Kind != "request" || events[1].Kind != "request" {
		t.Fatal(events)
	}
}

func TestDNP3ApplicationAssemblyFindings(t *testing.T) {
	frame := func(h byte) []byte { return linkFrame(0x44, []byte{0xc0, h, FuncResponse, 0, 0}) }
	for _, tc := range []struct {
		name string
		wire []byte
		code string
	}{
		{"duplicate", concat(frame(0xa1), frame(0xa1)), "dnp3.application_duplicate"},
		{"gap", concat(frame(0xa1), frame(0x43)), "dnp3.application_sequence"},
		{"restart", concat(frame(0xa1), frame(0xc2)), "dnp3.application_restart"},
		{"orphan", frame(0x42), "dnp3.application_sequence"},
		{"uns-function", frame(0xd1), "dnp3.application_control"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := parseAssembly(t, NewDecoder(), "s", dpi.ServerToClient, tc.wire)
			hasCode(t, events[len(events)-1], eventfields.KeyConformance, tc.code)
		})
	}
	d := NewDecoder()
	request := buildTestFrame(8, 0xc4, 10, 1, []byte{0xc0, 0xc5, FuncRead})
	reply := buildTestFrame(10, 0x44, 1, 10, []byte{0xc0, 0xc5, FuncResponse, 0, 0})
	parseAssembly(t, d, "s", dpi.ClientToServer, request)
	ev := expectOne(t, parseAssembly(t, d, "s", dpi.ServerToClient, reply))
	if ev.Attributes["request_matched"] != true || ev.Attributes["request_function_code"] != uint8(FuncRead) {
		t.Fatal(ev)
	}
}

func TestDNP3TransportAssemblyManagerCleanup(t *testing.T) {
	d := NewDecoder()
	mgr := dpi.NewManager(d)
	st := dnp3State()
	first := linkFrame(0x44, []byte{0x40, 0xc0, FuncResponse, 0, 0})
	result := mgr.Inspect(st, &dpi.ParsedPacket{Proto: "tcp", Session: "managed", Dir: dpi.ServerToClient, HasOffset: true, Offset: 0, Payload: first})
	if result.Err != nil || len(d.stations) != 1 {
		t.Fatal(result, len(d.stations))
	}
	mgr.EndStream("managed")
	if len(d.stations) != 0 || d.retained != 0 {
		t.Fatal("Manager did not dispatch StreamEnded")
	}
	result = mgr.Inspect(st, &dpi.ParsedPacket{Proto: "tcp", Session: "managed", Dir: dpi.ServerToClient, HasOffset: true, Offset: 0, Payload: linkFrame(0x44, []byte{0x81})})
	hasCode(t, expectOne(t, result.Events), eventfields.KeyConformance, "dnp3.transport_orphan")
}
