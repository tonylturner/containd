// SPDX-License-Identifier: Apache-2.0

package dpi

import "fmt"

// CoverageRange is a half-open carrying range [Start,End) in StreamView.Dir.
type CoverageRange struct{ Start, End int64 }

// ParsedUnit is immutable, decoder-validated protocol data. Concrete units live
// in their protocol packages and retain typed fields, not event JSON.
type ParsedUnit interface{ Protocol() string }

// ValidateDecodedFrame checks structural unit/coverage invariants without
// changing the frame or requiring a unit from legacy producers. It deliberately
// does not validate session/direction provenance: a session owner must verify
// earlier ranges against retained pending frames before authorizing any bytes.
// It is separate from the manager's physical framing/Consumed checks.
func ValidateDecodedFrame(f DecodedFrame) error {
	if f.Start < 0 || f.End <= f.Start {
		return fmt.Errorf("dpi: invalid physical frame range")
	}
	if f.Pending {
		if f.Unit != nil || f.Coverage != nil || len(f.Events) != 0 {
			return fmt.Errorf("dpi: pending frame carries a completed unit, coverage or events")
		}
		return nil
	}
	if f.Unit != nil && f.Unit.Protocol() == "" {
		return fmt.Errorf("dpi: unit has no protocol")
	}
	if f.Coverage == nil {
		return nil
	}
	if f.Unit != nil && (f.Unit.Protocol() == "modbus" || f.Unit.Protocol() == "iec104") {
		return fmt.Errorf("dpi: single-frame protocol must use implicit coverage")
	}
	if len(f.Coverage) == 0 || len(f.Coverage) > 1024 {
		return fmt.Errorf("dpi: coverage must contain 1..1024 ranges")
	}
	for i, r := range f.Coverage {
		if r.Start < 0 || r.End <= r.Start || r.End > f.End {
			return fmt.Errorf("dpi: invalid coverage range %d", i)
		}
		if i > 0 && r.Start < f.Coverage[i-1].End {
			return fmt.Errorf("dpi: unsorted or overlapping coverage range %d", i)
		}
	}
	last := f.Coverage[len(f.Coverage)-1]
	if last.Start > f.Start || last.End != f.End {
		return fmt.Errorf("dpi: coverage omits the completing physical frame")
	}
	return nil
}
