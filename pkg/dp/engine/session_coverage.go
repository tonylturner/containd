// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"fmt"
	"math/bits"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

// Retain physical provenance before authorizing any logical unit. Coverage may
// refer to earlier pending links, but never to an invented interval or a unit
// already decided at another physical offset. Validation stages only new frames
// and a compact coverage bitmap; retained metadata grows geometrically after
// validation. Refusal leaves both the old backing store and coverage unchanged.
func (t *sessionTable) retainFramesLocked(s *trackedSession, d *sessionDir, frames []dpi.DecodedFrame) error {
	if len(frames) == 0 {
		return nil
	}
	class := limits.ClassObserve
	if s.mode == "enforce" {
		class = limits.ClassEnforce
	}
	total := len(d.frames) + len(frames)
	words := 0
	for _, f := range frames {
		if err := dpi.ValidateDecodedFrame(f); err != nil {
			return err
		}
		if !f.Pending {
			words = (total + 63) / 64
		}
	}
	scratch, ok := t.resources.Budget.Reserve(class, limits.CategoryPairing, int64(len(frames))*128+int64(words)*8)
	if !ok {
		return flow.ErrInspectionLimit
	}
	defer scratch.Release()
	staged := make([]sessionFrame, len(frames))
	covered := make([]uint64, words)
	for i, f := range frames {
		staged[i] = sessionFrame{start: f.Start, end: f.End}
	}
	frameAt := func(i int) *sessionFrame {
		if i < len(d.frames) {
			return &d.frames[i]
		}
		return &staged[i-len(d.frames)]
	}
	for i, f := range frames {
		if f.Pending {
			continue
		}
		coverage := f.Coverage
		if coverage == nil {
			coverage = []dpi.CoverageRange{{Start: f.Start, End: f.End}}
		}
		for _, r := range coverage {
			next := r.Start
			for j := 0; j < len(d.frames)+i+1; j++ {
				p := frameAt(j)
				if p.end <= next {
					continue
				}
				mask := uint64(1) << (j % 64)
				if p.start != next || p.end > r.End || p.covered || covered[j/64]&mask != 0 {
					break
				}
				covered[j/64] |= mask
				next = p.end
				if next == r.End {
					break
				}
			}
			if next != r.End {
				return fmt.Errorf("unretained or already decided carrying range [%d,%d)", r.Start, r.End)
			}
		}
	}
	if total > cap(d.frames) {
		capacity := max(total, 2*cap(d.frames))
		lease, ok := t.resources.Budget.Reserve(class, limits.CategoryPairing, int64(capacity)*128)
		if !ok {
			return flow.ErrInspectionLimit
		}
		replacement := make([]sessionFrame, len(d.frames), capacity)
		copy(replacement, d.frames)
		old := d.frameLease
		d.frames, d.frameLease = replacement, lease
		if old != nil {
			old.Release()
		}
	}
	d.frames = append(d.frames, staged...)
	for word, mask := range covered {
		for mask != 0 {
			i := word*64 + bits.TrailingZeros64(mask)
			d.frames[i].covered = true
			mask &= mask - 1
		}
	}
	return nil
}

func (d *sessionDir) covered(start, end int64) bool {
	for _, f := range d.frames {
		if f.end <= start {
			continue
		}
		if f.start > start || !f.covered {
			return false
		}
		start = f.end
		if start >= end {
			return true
		}
	}
	return start >= end
}
func (d *sessionDir) nonAdmitting(start, end int64) bool {
	for _, f := range d.frames {
		if f.start >= end {
			break
		}
		if start < f.end && f.nonAdmit {
			return true
		}
	}
	return false
}
func nonAdmitWithResolved(pkt capture.Packet, resolved []capture.Resolution) capture.Decision {
	d := nonAdmitDecision(pkt)
	d.Resolved = resolved
	return d
}
