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
)

// These tests feed events produced by the real decoders, whose numeric
// attributes are concrete uint8/uint16 values, and the same events after a
// JSON round trip (float64). Hand-built int attributes hid the drift.

func decodeOne(t *testing.T, d dpi.Decoder, dstPort uint16, payload []byte) dpi.Event {
	t.Helper()
	key := flow.Key{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"), SrcPort: 40000, DstPort: dstPort, Proto: 6}
	return decodeOneWithKey(t, d, key, payload)
}

func decodeOneWithKey(t *testing.T, d dpi.Decoder, key flow.Key, payload []byte) dpi.Event {
	t.Helper()
	evs, err := d.OnPacket(flow.NewState(key, time.Now()), &dpi.ParsedPacket{
		Payload: payload, Proto: "tcp", SrcPort: key.SrcPort, DstPort: key.DstPort,
	})
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

func modbusRead(unit uint8) []byte {
	// MBAP: txn 1, proto 0, length 6, unit; PDU: FC 3 read register 1, count 1.
	return []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, unit, 0x03, 0x00, 0x01, 0x00, 0x01}
}

func modbusException(unit uint8) []byte {
	// MBAP: txn 1, proto 0, length 3, unit; PDU: FC 3 exception, code 2.
	return []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x03, unit, 0x83, 0x02}
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

func TestDecodedModbusExceptionCompletesRequest(t *testing.T) {
	clientIP, serverIP := "10.0.0.1", "10.0.0.2"
	requestKey := flow.Key{
		SrcIP: net.ParseIP(clientIP), DstIP: net.ParseIP(serverIP),
		SrcPort: 40000, DstPort: 502, Proto: 6, Dir: flow.DirForward,
	}
	exceptionKey := flow.Key{
		SrcIP: net.ParseIP(serverIP), DstIP: net.ParseIP(clientIP),
		SrcPort: 502, DstPort: 40000, Proto: 6, Dir: flow.DirReverse,
	}

	for _, roundTrip := range []bool{false, true} {
		t.Run(map[bool]string{false: "decoded", true: "json_round_trip"}[roundTrip], func(t *testing.T) {
			request := decodeOneWithKey(t, modbus.NewDecoder(), requestKey, modbusRead(1))
			exception := decodeOneWithKey(t, modbus.NewDecoder(), exceptionKey, modbusException(1))
			if exception.Kind != "exception" {
				t.Fatalf("decoder event kind changed: got %q", exception.Kind)
			}
			if roundTrip {
				request, exception = jsonRoundTrip(t, request), jsonRoundTrip(t, exception)
			}

			d := New()
			if got := d.Check(clientIP, serverIP, request); len(got) != 0 {
				t.Fatalf("decoded request produced unexpected anomalies: %+v", got)
			}
			if got := d.Check(serverIP, clientIP, exception); len(got) != 0 {
				t.Fatalf("decoded exception should complete its request: %+v", got)
			}
			if d.pendingTxns[flowKey(clientIP, serverIP)][1] {
				t.Fatal("decoded exception did not remove its pending transaction")
			}
		})
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

func TestFractionalFunctionCodeIsAbsent(t *testing.T) {
	ev := dpi.Event{Proto: "dnp3", Kind: "request", Attributes: map[string]any{"function_code": 13.5}}
	if got := New().Check("10.0.0.1", "10.0.0.2", ev); len(got) != 0 {
		t.Fatalf("fractional FC must not truncate to 13: %+v", got)
	}
}
