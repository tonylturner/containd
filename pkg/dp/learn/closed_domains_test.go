// SPDX-License-Identifier: Apache-2.0
package learn

import (
	"encoding/binary"
	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/ics/project"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"net"
	"slices"
	"testing"

	"github.com/tonylturner/containd/pkg/evidence"
)

func TestIECCommandRequirementsBoundByPredicates(t *testing.T) {
	for _, typeID := range []uint8{45, 46, 47, 58, 59, 60} {
		ioa, state, q := uint32(7), uint8(1), uint8(0)
		p := evidence.Observation{IEC104: &evidence.IEC104{TypeID: &typeID, Objects: []evidence.IEC104Object{{IOA: &ioa, CommandState: &state, Qualifier: &q}}}}
		if reasons := closedDomains([]evidence.Observation{p}); len(reasons) != 0 {
			t.Fatalf("partial command %d withheld: %v", typeID, reasons)
		}
	}
	for _, typeID := range []uint8{48, 49, 50, 51, 61, 62, 63, 64} {
		ioa, q := uint32(7), uint8(0)
		p := evidence.Observation{IEC104: &evidence.IEC104{TypeID: &typeID, Objects: []evidence.IEC104Object{{IOA: &ioa, Qualifier: &q, ValueDigest: "unbounded"}}}}
		reasons := closedDomains([]evidence.Observation{p})
		if !slices.Contains(reasons, evidence.WithheldIECValue) || !slices.Contains(reasons, evidence.WithheldIECQualifier) {
			t.Fatalf("setpoint/bitstring %d not withheld: %v", typeID, reasons)
		}
	}
}
func TestModbusClosedCoilDomain(t *testing.T) {
	unit, fc := uint8(1), uint8(5)
	parent := evidence.Observation{Quality: evidence.Quality{Complete: true, Decoded: true}, Authority: evidence.Authority{RoleCertain: true, RoleEvidence: PortDecoderAuthority, StandardPort: true}, Service: evidence.ServiceKey{ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ServerPort: 502, Transport: "tcp", Direction: "request", Protocol: "modbus"}, Modbus: &evidence.Modbus{UnitID: &unit, FunctionCode: &fc, Spans: []evidence.Span{{First: 7, Last: 7}}, Values: []uint16{0}}}
	bundle, reasons := GenerateRelation(parent)
	if len(reasons) != 0 {
		t.Fatal(reasons)
	}
	cfg := config.DefaultConfig()
	cfg.Firewall.Rules = bundle
	snap, err := compile.CompileSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	evaluator := rules.NewEvaluator(&snap)
	state := flow.NewState(flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), SrcPort: 40000, DstPort: 502, Proto: 6}, parent.CapturedAt)
	decoder := modbus.NewDecoder()
	raw := []byte{0, 1, 0, 0, 0, 6, 1, 5, 0, 7, 0, 0}
	// Exhaust the actual 16-bit wire space, not the generator's assumed set.
	for value := range 1 << 16 {
		binary.BigEndian.PutUint16(raw[10:], uint16(value))
		events, err := decoder.OnPacket(state, &dpi.ParsedPacket{Payload: raw})
		if err != nil || len(events) != 1 {
			t.Fatal("decode", err)
		}
		objects := project.Objects(state, events[0], nil)
		match := evaluator.AnyMatch(rules.EvalContext{SrcIP: state.Key.SrcIP, DstIP: state.Key.DstIP, Proto: "tcp", Port: "502", ICS: &objects[0]}) != nil
		if match != (value == 0 || value == 0xff00) {
			t.Fatalf("closed domain admits wire value %#x: %v", value, match)
		}
	}
	if EvaluatorVersion != rules.EvaluatorVersion {
		t.Fatal("proof evaluator version is not owned by the runtime predicate")
	}
}
func TestDNPWithholdingIsPerHeader(t *testing.T) {
	group, variation, qualifier := uint8(12), uint8(1), uint8(0x17)
	count := uint32(1)
	obj := evidence.DNP3Object{Group: &group, Variation: &variation, Qualifier: &qualifier, Count: &count, Spans: []evidence.Span{{First: 2, Last: 2}}}
	if len(dnpRequirements(obj)) != 0 {
		t.Fatal("bounded header withheld")
	}
	obj.AllObjects = true
	if !slices.Contains(dnpRequirements(obj), evidence.WithheldDNP3AllObjects) {
		t.Fatal("all-objects not withheld")
	}
}

func TestDNPClosedDomainsMatchDecodedWireValues(t *testing.T) {
	for _, group := range []uint8{1, 3, 10, 80} {
		variation, count := uint8(1), uint32(4)
		domain := dnpValueDomain(evidence.DNP3Object{Group: &group, Variation: &variation, Count: &count})
		for value := range 256 {
			headers := dnp3.ParseObjectHeaders([]byte{group, 1, 0, 0, 3, byte(value)}, 0, 2)
			if len(headers) != 1 || !domain[headers[0].DataDigest] {
				t.Fatalf("packed group %d wire byte %#x is outside declared runtime domain: %+v", group, value, headers)
			}
		}
	}
}
