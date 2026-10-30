// SPDX-License-Identifier: Apache-2.0
package learn

import (
	"github.com/tonylturner/containd/pkg/evidence"
	"slices"
	"testing"
)

func TestIECClosedValueDomain(t *testing.T) {
	for _, tc := range []struct {
		typeID uint8
		values []uint8
	}{{45, []uint8{0, 1}}, {46, []uint8{1, 2}}} {
		var parents []evidence.Observation
		ioa := uint32(7)
		for _, value := range tc.values {
			digest, _ := evidence.Digest(value)
			parents = append(parents, evidence.Observation{IEC104: &evidence.IEC104{TypeID: &tc.typeID, Objects: []evidence.IEC104Object{{IOA: &ioa, ValueDigest: digest}}}})
		}
		if reasons := closedDomains(parents[:1]); !slices.Contains(reasons, evidence.WithheldIECValue) {
			t.Fatalf("strict subset accepted: %+v", reasons)
		}
		if reasons := closedDomains(parents); slices.Contains(reasons, evidence.WithheldIECValue) {
			t.Fatalf("whole closed domain withheld: %+v", reasons)
		}
	}
}
func TestModbusClosedCoilDomain(t *testing.T) {
	fc := uint8(5)
	parents := []evidence.Observation{{Modbus: &evidence.Modbus{FunctionCode: &fc, Values: []uint16{0}}}, {Modbus: &evidence.Modbus{FunctionCode: &fc, Values: []uint16{0xff00}}}}
	if len(modbusDomains(parents[:1])) == 0 {
		t.Fatal("strict subset accepted")
	}
	if len(modbusDomains(parents)) != 0 {
		t.Fatal("whole domain withheld")
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
