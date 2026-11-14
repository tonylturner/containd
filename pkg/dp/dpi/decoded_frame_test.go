// SPDX-License-Identifier: Apache-2.0

package dpi

import (
	"reflect"
	"testing"
)

type classSchemaUnit string

func (u classSchemaUnit) Protocol() string { return string(u) }

func TestPairingClassSchemaDecodedFrame(t *testing.T) {
	tests := []struct {
		name  string
		frame DecodedFrame
		valid bool
	}{
		{"legacy", DecodedFrame{Start: 5, End: 10, Events: []Event{{Proto: "modbus"}}}, true},
		{"typedZeroEvents", DecodedFrame{Start: 5, End: 10, Unit: classSchemaUnit("modbus")}, true},
		{"pending", DecodedFrame{Start: 5, End: 10, Pending: true}, true},
		{"discontiguousEarlierRanges", DecodedFrame{Start: 20, End: 30, Unit: classSchemaUnit("dnp3"), Coverage: []CoverageRange{{0, 10}, {20, 30}}}, true},
		{"adjacent", DecodedFrame{Start: 20, End: 30, Coverage: []CoverageRange{{0, 20}, {20, 30}}}, true},
		{"negativePhysical", DecodedFrame{Start: -1, End: 10}, false},
		{"emptyPhysical", DecodedFrame{Start: 10, End: 10}, false},
		{"reversedPhysical", DecodedFrame{Start: 10, End: 5}, false},
		{"pendingUnit", DecodedFrame{Start: 5, End: 10, Pending: true, Unit: classSchemaUnit("dnp3")}, false},
		{"pendingEvents", DecodedFrame{Start: 5, End: 10, Pending: true, Events: []Event{{}}}, false},
		{"pendingCoverage", DecodedFrame{Start: 5, End: 10, Pending: true, Coverage: []CoverageRange{{5, 10}}}, false},
		{"emptyProtocol", DecodedFrame{Start: 5, End: 10, Unit: classSchemaUnit("")}, false},
		{"modbusExplicitCoverage", DecodedFrame{Start: 5, End: 10, Unit: classSchemaUnit("modbus"), Coverage: []CoverageRange{{5, 10}}}, false},
		{"iecExplicitCoverage", DecodedFrame{Start: 5, End: 10, Unit: classSchemaUnit("iec104"), Coverage: []CoverageRange{{5, 10}}}, false},
		{"emptyCoverage", DecodedFrame{Start: 5, End: 10, Coverage: []CoverageRange{}}, false},
		{"negativeCoverage", DecodedFrame{Start: 5, End: 10, Coverage: []CoverageRange{{-1, 10}}}, false},
		{"emptyRange", DecodedFrame{Start: 5, End: 10, Coverage: []CoverageRange{{5, 5}}}, false},
		{"reversedRange", DecodedFrame{Start: 5, End: 10, Coverage: []CoverageRange{{6, 5}}}, false},
		{"futureRange", DecodedFrame{Start: 5, End: 10, Coverage: []CoverageRange{{5, 11}}}, false},
		{"overlapping", DecodedFrame{Start: 5, End: 10, Coverage: []CoverageRange{{0, 6}, {5, 10}}}, false},
		{"unsorted", DecodedFrame{Start: 5, End: 10, Coverage: []CoverageRange{{5, 10}, {0, 5}}}, false},
		{"missingCompletingPrefix", DecodedFrame{Start: 5, End: 10, Coverage: []CoverageRange{{6, 10}}}, false},
		{"missingCompletingTail", DecodedFrame{Start: 5, End: 10, Coverage: []CoverageRange{{0, 9}}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]CoverageRange(nil), tc.frame.Coverage...)
			if err := ValidateDecodedFrame(tc.frame); (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
			if len(before) > 0 && !reflect.DeepEqual(before, tc.frame.Coverage) {
				t.Fatal("validation changed ranges")
			}
		})
	}
	t.Run("rangeBound", func(t *testing.T) {
		ranges := make([]CoverageRange, 1025)
		for i := range ranges {
			ranges[i] = CoverageRange{int64(i * 2), int64(i*2 + 1)}
		}
		f := DecodedFrame{Start: 2046, End: 2047, Coverage: ranges[:1024]}
		if err := ValidateDecodedFrame(f); err != nil {
			t.Fatal("rejected maximum range count:", err)
		}
		f.Start, f.End, f.Coverage = 2048, 2049, ranges
		if err := ValidateDecodedFrame(f); err == nil {
			t.Fatal("accepted over 1024 carrying ranges")
		}
	})
	t.Run("legacyInspect", func(t *testing.T) {
		mgr, _, st := framedFixture()
		result := mgr.Inspect(st, sessionSeg("class-schema", ClientToServer, 0, 2, 0xa1, 0xa2))
		if result.Err != nil || len(result.Frames) != 1 || len(result.Events) != 1 {
			t.Fatalf("legacy producer no longer works: %+v", result)
		}
		f := result.Frames[0]
		if f.Coverage != nil || f.Pending || f.Unit != nil {
			t.Fatalf("legacy metadata changed: %+v", f)
		}
		if err := ValidateDecodedFrame(f); err != nil {
			t.Fatal(err)
		}
		view := StreamView{Bytes: []byte{2, 0xa1, 0xa2}}
		sr := StreamResult{Frames: result.Frames, Consumed: 3}
		if why := frameContractViolation(view, sr, true); why != "" {
			t.Fatal(why)
		}
		sr.Consumed--
		if why := frameContractViolation(view, sr, true); why == "" {
			t.Fatal("Consumed invariant relaxed")
		}
	})
}
