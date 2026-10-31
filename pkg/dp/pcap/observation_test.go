// SPDX-License-Identifier: Apache-2.0

package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// decodedEvents isolates decoder output for legacy framing/orientation tests.
// Identification events are tested separately, including their exact count.
func decodedEvents(events []dpi.Event) []dpi.Event {
	var out []dpi.Event
	for _, ev := range events {
		if ev.Proto != "identify" {
			out = append(out, ev)
		}
	}
	return out
}

func TestIdentificationFixtures(t *testing.T) {
	for _, tc := range []struct {
		name, protocol, binding, state string
		mismatch                       bool
		events                         int
	}{
		{"modbus-1502", "modbus", "observation", "confirmed", false, 2},
		{"iec104-12404", "iec104", "observation", "confirmed", false, 2},
		{"modbus-20000", "modbus", "observation", "confirmed", true, 2},
		{"modbus-502", "modbus", "legacy", "confirmed", false, 2},
		{"midstream", "", "none", "identification_incomplete", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile("testdata/" + tc.name + ".pcap")
			if err != nil {
				t.Fatal(err)
			}
			now := time.Unix(100, 0)
			result, err := AnalyzeWithOptions(bytes.NewReader(data), AnalysisOptions{Now: func() time.Time { return now }}, modbus.NewDecoder(), dnp3.NewDecoder(), iec104.NewDecoder())
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Identifications) != 1 {
				t.Fatalf("identifications: %+v", result.Identifications)
			}
			if _, ok := result.Protocols["identify"]; ok {
				t.Fatalf("identification counted as a protocol: %+v", result.Protocols)
			}
			identificationEvents, flowEvents := 0, 0
			for _, ev := range result.Events {
				if ev.Proto == "identify" {
					identificationEvents++
				}
			}
			for _, f := range result.Flows {
				flowEvents += f.Events
			}
			if identificationEvents != 1 || flowEvents != len(result.Events) {
				t.Fatalf("lost flow events: identifications=%d flows=%d events=%d", identificationEvents, flowEvents, len(result.Events))
			}
			a := result.Identifications[0].Attributes
			if a["protocol"] != tc.protocol || a["binding"] != tc.binding || a["identification_state"] != tc.state || a["mismatch"] != tc.mismatch || a["outside_rule_port_scope"] != "unknown" {
				t.Fatalf("attributes: %+v", a)
			}
			count := 0
			for _, ev := range result.Events {
				if ev.Proto == tc.protocol && ev.Kind != "malformed" {
					count++
					if (ev.Attributes["observation_only"] == true) != (tc.binding == "observation") {
						t.Fatalf("marker: %+v", ev)
					}
					if ev.Connection == nil || ev.Connection.Key != result.Identifications[0].Key {
						t.Fatalf("key: %+v", ev)
					}
				}
			}
			if count != tc.events {
				t.Fatalf("decoded %d want %d: %+v", count, tc.events, result.Events)
			}

		})
	}
}

func TestIdentificationEndpoints(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		reverse                  bool
		clientPort, serverPort   uint16
		flags                    byte
		wantSrc, wantDst         string
		wantSrcPort, wantDstPort uint16
	}{
		{"SYN", false, 49152, 1502, 0x02, "10.0.0.1", "10.0.0.2", 49152, 1502},
		{"SYN overrides registry port", false, 502, 1502, 0x02, "10.0.0.1", "10.0.0.2", 502, 1502},
		{"SYN-ACK first", true, 49152, 1502, 0x12, "10.0.0.1", "10.0.0.2", 49152, 1502},
		{"unknown midstream keeps capture order", true, 49152, 1502, 0x10, "10.0.0.2", "10.0.0.1", 1502, 49152},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := orientedModbusFrame(tc.reverse, tc.clientPort, tc.serverPort, 99, tc.flags, nil)
			result, err := Analyze(bytes.NewReader(buildPCAP([][]byte{frame})), modbus.NewDecoder())
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Identifications) != 1 {
				t.Fatalf("identifications: %+v", result.Identifications)
			}
			id := result.Identifications[0]
			if id.SrcIP != tc.wantSrc || id.DstIP != tc.wantDst || id.SrcPort != tc.wantSrcPort || id.DstPort != tc.wantDstPort {
				t.Fatalf("endpoints: %+v", id)
			}
		})
	}
}

func TestOutsideRulePorts(t *testing.T) {
	for _, tc := range []struct {
		protocols []rules.Protocol
		port      uint16
		want      bool
	}{
		{nil, 1502, true}, {nil, 502, false}, {[]rules.Protocol{{Name: "tcp", Port: "1500-1510"}}, 1502, false},
		{[]rules.Protocol{{Name: "udp", Port: "1502"}}, 1502, true}, {[]rules.Protocol{{Name: "tcp"}}, 1502, false},
	} {
		snap := &rules.Snapshot{Firewall: []rules.Entry{{ICS: rules.ICSPredicate{Protocol: "modbus"}, Protocols: tc.protocols}}}
		if got := outsideRulePorts(snap, "modbus", 6, tc.port); got != tc.want {
			t.Fatalf("%+v got %v", tc, got)
		}
	}
	if outsideRulePorts(&rules.Snapshot{}, "modbus", 6, 1502) {
		t.Fatal("no named rule")
	}
}

func TestObservationIncarnationsReplayAndClock(t *testing.T) {
	frame := func(reverse bool, seq uint32, flags byte, payload []byte) []byte {
		return orientedModbusFrame(reverse, 49152, 1502, seq, flags, payload)
	}
	request := modbusADU(1, 3, 0, 2)
	response := []byte{0, 1, 0, 0, 0, 7, 1, 3, 4, 0, 10, 0, 11}
	frames := [][]byte{
		frame(false, 99, 2, nil), frame(false, 99, 2, nil), frame(true, 499, 0x12, nil),
		frame(false, 100, 0x18, request[:5]), frame(false, 105, 0x18, request[5:]),
		frame(true, 500, 0x18, response), frame(false, 100, 0x18, request),
		// A FIN carrying payload is decoded before close; the peer remains open.
		frame(false, 112, 0x19, modbusADU(2, 3, 0, 2)), frame(true, 513, 0x19, response),
		// A different ISN on this tuple is a separate incarnation.
		frame(false, 999, 2, nil), frame(true, 1499, 0x12, nil),
		frame(false, 1000, 0x18, request), frame(true, 1500, 0x18, response),
	}
	now := time.Unix(100, 0)
	result, err := AnalyzeWithOptions(bytes.NewReader(buildPCAP(frames)), AnalysisOptions{Now: func() time.Time { return now }, Rules: &rules.Snapshot{Firewall: []rules.Entry{{ICS: rules.ICSPredicate{Protocol: "modbus"}}}}}, modbus.NewDecoder())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Identifications) != 2 || result.Identifications[0].Key == result.Identifications[1].Key {
		t.Fatalf("incarnations: %+v", result.Identifications)
	}
	for _, id := range result.Identifications {
		if id.Attributes["binding"] != "observation" || id.Attributes["outside_rule_port_scope"] != true {
			t.Fatalf("%+v", id)
		}
	}
	// Capture timestamps span more than the evidence budget, but the injected
	// ingestion clock has not advanced: both identifications must confirm.
	if got := result.Protocols["modbus"]; got != 6 {
		t.Fatalf("decoded=%d events=%+v", got, result.Events)
	}
	for _, ev := range decodedEvents(result.Events) {
		if ev.Timestamp.Year() != 2025 || ev.Attributes["observation_only"] != true {
			t.Fatalf("stamp/marker: %+v", ev)
		}
	}
}

func TestObservationEOFFinalizesPending(t *testing.T) {
	frames := [][]byte{orientedModbusFrame(false, 49152, 1502, 99, 2, nil)}
	result, err := Analyze(bytes.NewReader(buildPCAP(frames)), modbus.NewDecoder())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Identifications) != 1 || result.Identifications[0].Attributes["identification_coverage"] != "closed" {
		t.Fatalf("%+v", result.Identifications)
	}
}

func TestObservationCaptureDeadline(t *testing.T) {
	frames := [][]byte{
		orientedModbusFrame(false, 49152, 1502, 99, 2, nil),
		orientedModbusFrame(true, 49152, 1502, 499, 0x12, nil),
	}
	data := buildPCAP(frames)
	// The second capture arrival is beyond the evidence window. Deadlines
	// follow capture time, not the speed at which this file is analyzed.
	second := 24 + 16 + len(frames[0])
	first := binary.LittleEndian.Uint32(data[24:])
	binary.LittleEndian.PutUint32(data[second:], first+6)
	result, err := Analyze(bytes.NewReader(data), modbus.NewDecoder())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Identifications) != 1 || result.Identifications[0].Attributes["identification_coverage"] != "timeout" {
		t.Fatalf("%+v", result.Identifications)
	}
}

func TestObservationTruncatedCapture(t *testing.T) {
	for _, partialIP := range []bool{false, true} {
		t.Run(fmt.Sprint(partialIP), func(t *testing.T) {
			payload := orientedModbusFrame(false, 49152, 1502, 100, 0x18, modbusADU(1, 3, 0, 2))
			if partialIP {
				payload = payload[:len(payload)-1]
			}
			frames := [][]byte{orientedModbusFrame(false, 49152, 1502, 99, 2, nil), payload}
			data := buildPCAP(frames)
			second := 24 + 16 + len(frames[0])
			binary.LittleEndian.PutUint32(data[second+12:], uint32(len(payload)+1))
			result, err := Analyze(bytes.NewReader(data), modbus.NewDecoder())
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Identifications) != 1 || result.Identifications[0].Attributes["identification_coverage"] != "truncated" {
				t.Fatalf("%+v", result.Identifications)
			}
			if result.Protocols["modbus"] != 0 {
				t.Fatal("decoded incomplete observation")
			}
		})
	}
}
