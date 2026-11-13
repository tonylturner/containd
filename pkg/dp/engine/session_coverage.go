// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

// Retain physical provenance before authorizing any logical unit. Coverage may
// refer to earlier pending links, but never to an invented interval or a unit
// already decided at another physical offset. The replacement is published only
// after every range is validated, so refusal cannot release a decided prefix.
func (t *sessionTable) retainFramesLocked(s *trackedSession, d *sessionDir, frames []dpi.DecodedFrame) error {
	if len(frames) == 0 {
		return nil
	}
	class := limits.ClassObserve
	if s.mode == "enforce" {
		class = limits.ClassEnforce
	}
	lease, ok := t.resources.Budget.Reserve(class, limits.CategoryPairing, int64(len(d.frames)+len(frames))*32)
	if !ok {
		return flow.ErrInspectionLimit
	}
	replacement := make([]sessionFrame, len(d.frames)+len(frames))
	copy(replacement, d.frames)
	for i, f := range frames {
		if err := dpi.ValidateDecodedFrame(f); err != nil {
			lease.Release()
			return err
		}
		replacement[len(d.frames)+i] = sessionFrame{start: f.Start, end: f.End}
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
			for j := range replacement[:len(d.frames)+i+1] {
				p := &replacement[j]
				if p.end <= next {
					continue
				}
				if p.start != next || p.end > r.End || p.covered {
					break
				}
				p.covered = true
				next = p.end
				if next == r.End {
					break
				}
			}
			if next != r.End {
				lease.Release()
				return fmt.Errorf("unretained or already decided carrying range [%d,%d)", r.Start, r.End)
			}
		}
	}
	old := d.frameLease
	d.frames, d.frameLease = replacement, lease
	if old != nil {
		old.Release()
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
