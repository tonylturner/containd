// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package anomaly

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/ics/s7comm"
)

// These tests feed events produced by the real decoders, whose numeric
// attributes are concrete uint8/uint16 values, and the same events after a
// JSON round trip (float64). Hand-built int attributes hid the drift.

func decodeOne(t *testing.T, d dpi.Decoder, dstPort uint16, payload []byte) dpi.Event {
	t.Helper()
	key := flow.Key{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"), SrcPort: 40000, DstPort: dstPort, Proto: 6}
	evs, err := d.OnPacket(flow.NewState(key, time.Now()), &dpi.ParsedPacket{Payload: payload, Proto: "tcp", SrcPort: 40000, DstPort: dstPort})
	if err != nil || len(evs) != 1 {
		t.Fatalf("decode: events=%d err=%v", len(evs), err)
	}
	return evs[0]
}

func jsonRoundTrip(t *testing.T, ev dpi.Event) dpi.Event {
	t.Helper()
	raw, err := json.Marshal(ev.Attributes)
	if err != nil {
		t.Fatal(err)
	}
	var attrs map[string]any
	if err := json.Unmarshal(raw, &attrs); err != nil {
		t.Fatal(err)
	}
	ev.Attributes = attrs
	return ev
}

func modbusWrite(unit uint8) []byte {
	// MBAP: txn 1, proto 0, length 6, unit; PDU: FC 6 write register 1 = 3.
	return []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, unit, 0x06, 0x00, 0x01, 0x00, 0x03}
}

func hasMessage(as []Anomaly, msg string) bool {
	for _, a := range as {
		if a.Message == msg {
			return true
		}
	}
	return false
}

func TestDecodedModbusUnitIDDrift(t *testing.T) {
	const broadcast = "Broadcast unit ID 0 used for write operation"
	for _, rt := range []bool{false, true} {
		unicast := decodeOne(t, modbus.NewDecoder(), 502, modbusWrite(1))
		bcast := decodeOne(t, modbus.NewDecoder(), 502, modbusWrite(0))
		if rt {
			unicast, bcast = jsonRoundTrip(t, unicast), jsonRoundTrip(t, bcast)
		}
		if got := New().Check("10.0.0.1", "10.0.0.2", unicast); hasMessage(got, broadcast) {
			t.Fatalf("roundtrip=%v: unit 1 write flagged as broadcast: %+v", rt, got)
		}
		if got := New().Check("10.0.0.1", "10.0.0.2", bcast); !hasMessage(got, broadcast) {
			t.Fatalf("roundtrip=%v: unit 0 write not flagged: %+v", rt, got)
		}
	}
}

func TestModbusAbsentUnitIsNotBroadcast(t *testing.T) {
	ev := dpi.Event{Proto: "modbus", Kind: "request", Attributes: map[string]any{"function_code": uint8(6), "is_write": true}}
	if got := New().Check("10.0.0.1", "10.0.0.2", ev); hasMessage(got, "Broadcast unit ID 0 used for write operation") {
		t.Fatalf("absent unit_id read as 0: %+v", got)
	}
}

// dnp3Frame builds a single-block DNP3 link frame with valid CRCs.
func dnp3Frame(control byte, user []byte) []byte {
	hdr := []byte{0x05, 0x64, byte(5 + len(user)), control, 0x01, 0x00, 0x02, 0x00}
	out := binary.LittleEndian.AppendUint16(append([]byte(nil), hdr...), dnp3CRC(hdr))
	out = append(out, user...)
	return binary.LittleEndian.AppendUint16(out, dnp3CRC(user))
}

func dnp3CRC(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xA6BC
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

func TestDecodedDNP3FunctionCodeDrift(t *testing.T) {
	const unsolicited = "DNP3 unsolicited response (FC 130) detected"
	// Transport FIR|FIN, app control, FC 130 (unsolicited response), IIN.
	ev := decodeOne(t, dnp3.NewDecoder(), 20000, dnp3Frame(0x44, []byte{0xC0, 0xF0, 0x82, 0x00, 0x00}))
	for _, e := range []dpi.Event{ev, jsonRoundTrip(t, ev)} {
		if got := New().Check("10.0.0.2", "10.0.0.1", e); !hasMessage(got, unsolicited) {
			t.Fatalf("FC 130 not read from decoded event %v: %+v", e.Attributes, got)
		}
	}
}

func TestDecodedS7FunctionCodeDrift(t *testing.T) {
	const stop = "S7comm PLC Stop command detected (FC 0x29)"
	// TPKT + COTP DT + S7 job header with a PLC stop parameter (0x29).
	param := []byte{0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x50, 0x5F, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D}
	s7 := []byte{0x32, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, byte(len(param)), 0x00, 0x00}
	s7 = append(s7, param...)
	// The decoder's COTP DT type constant is 0x0F (s7comm/frame.go), so the
	// fixture uses it; on the wire DT is 0xF0.
	cotp := append([]byte{0x02, 0x0F, 0x80}, s7...)
	tpkt := binary.BigEndian.AppendUint16([]byte{0x03, 0x00}, uint16(4+len(cotp)))
	ev := decodeOne(t, s7comm.NewDecoder(), 102, append(tpkt, cotp...))
	for _, e := range []dpi.Event{ev, jsonRoundTrip(t, ev)} {
		if got := New().Check("10.0.0.1", "10.0.0.2", e); !hasMessage(got, stop) {
			t.Fatalf("FC 0x29 not read from decoded event %v: %+v", e.Attributes, got)
		}
	}
}

func TestFractionalFunctionCodeIsAbsent(t *testing.T) {
	ev := dpi.Event{Proto: "s7comm", Kind: "request", Attributes: map[string]any{"function_code": 41.5}}
	if got := New().Check("10.0.0.1", "10.0.0.2", ev); len(got) != 0 {
		t.Fatalf("fractional FC must not truncate to 41: %+v", got)
	}
}
