// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"maps"
	"sync"
	"time"

	wire "github.com/tonylturner/containd/pkg/common/telemetry"
)

// Sampler has one writer. Source failures are independent: engine outages
// cannot suppress the management-local counters.
type Sampler struct {
	store    *Store
	readers  []wire.CounterReader
	previous map[string]previous
	mu       sync.Mutex
}

func NewSampler(store *Store, readers ...wire.CounterReader) *Sampler {
	return &Sampler{store: store, readers: readers, previous: map[string]previous{}}
}

// Tick is also the deterministic clock boundary used by tests. mono must be
// process-monotonic elapsed time, independent of the wall clock.
func (s *Sampler) Tick(ctx context.Context, wall time.Time, mono time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	samples := []wire.CounterSample{}
	invalid := []wire.CounterSample{}
	for _, reader := range s.readers {
		if reader == nil {
			continue
		}
		readCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		snapshot, err := reader.TelemetryCounters(readCtx)
		cancel()
		if err == nil {
			samples = append(samples, snapshot.Samples...)
			if local, ok := reader.(interface{ TelemetryBaselines() []wire.CounterSample }); ok {
				invalid = append(invalid, local.TelemetryBaselines()...)
			}
		}
	}
	// A management signed correction invalidates the baseline, rather than
	// masquerading as a source reset or a positive spanning delta.
	for _, sample := range invalid {
		delete(s.previous, identity(sample))
	}

	rows := make([]row, 0, len(samples)+len(s.previous))
	next := make(map[string]previous, len(s.previous))
	for k, p := range s.previous {
		next[k] = p
	}
	seen := map[string]bool{}
	for _, sample := range samples {
		sample.Dims = maps.Clone(sample.Dims)
		key := identity(sample)
		if seen[key] {
			continue
		}
		seen[key] = true
		p := wire.Point{}
		if prev, ok := s.previous[key]; ok {
			var accept bool
			p, accept = delta(prev, sample, wall, mono)
			if !accept {
				continue
			}
		}
		rows = append(rows, row{sample: sample, point: p})
		next[key] = previous{sample: sample, wall: wall, mono: mono}
	}
	for key, prev := range s.previous {
		if seen[key] {
			continue
		}
		slot, _ := sampleSlot(wall)
		rows = append(rows, row{sample: prev.sample, point: wire.Point{T: slot.Add(-Resolution), Q: wire.QualityGap}, missing: true})
		// Preserve the previous successful reading for a spanning delta, but
		// bound stale in-memory state just like series metadata.
		if wall.Sub(prev.wall) > 30*24*time.Hour {
			delete(next, key)
		}
	}
	err := s.store.write(ctx, wall, rows)
	admitted := s.store.admittedKeys()
	for key := range next {
		if !admitted[key] {
			delete(next, key)
		}
	}
	s.previous = next
	return err
}

func nextTick(now time.Time) time.Time {
	next := now.Truncate(Resolution).Add(sampleOffset)
	if !next.After(now) {
		next = next.Add(Resolution)
	}
	return next
}

// Run returns only after the writer has stopped, allowing the owner to close
// its database safely after cancelling the context.
func (s *Sampler) Run(ctx context.Context) {
	started := time.Now()
	for {
		timer := time.NewTimer(time.Until(nextTick(time.Now())))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			now := time.Now()
			_ = s.Tick(ctx, now, now.Sub(started)) // write failure is exposed in CollectorState
		}
	}
}
