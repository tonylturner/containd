// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package events

import (
	"sort"
	"sync/atomic"

	"github.com/tonylturner/containd/pkg/common/telemetry"
)

type eventTelemetryCounters struct {
	total   atomic.Uint64
	classes [4]atomic.Uint64
}

var eventClasses = [...]telemetry.EventClass{
	telemetry.ClassIDSAlert,
	telemetry.ClassAVDetection,
	telemetry.ClassAVBlock,
	telemetry.ClassModbusWrite,
}

func newEventTelemetryCounters() map[telemetry.Origin]*eventTelemetryCounters {
	return map[telemetry.Origin]*eventTelemetryCounters{
		telemetry.OriginReal: {},
		telemetry.OriginDemo: {},
	}
}

func (s *Store) incrementTelemetryCounts(ev Event) {
	origin := ev.Origin
	if origin == "" {
		origin = telemetry.OriginReal
	}

	s.telemetryMu.RLock()
	counts := s.telemetryCounters[origin]
	s.telemetryMu.RUnlock()
	if counts == nil {
		s.telemetryMu.Lock()
		counts = s.telemetryCounters[origin]
		if counts == nil {
			counts = &eventTelemetryCounters{}
			s.telemetryCounters[origin] = counts
		}
		s.telemetryMu.Unlock()
	}

	counts.total.Add(1)
	for _, class := range Classify(ev) {
		counts.classes[eventClassIndex(class)].Add(1)
	}
}

func eventClassIndex(class telemetry.EventClass) int {
	for i, candidate := range eventClasses {
		if class == candidate {
			return i
		}
	}
	panic("unknown event class")
}

// TelemetryCounts returns a cumulative counter snapshot for every origin.
// The real and demo origins are always present, including before any events.
func (s *Store) TelemetryCounts() []telemetry.EventCounts {
	if s == nil {
		return []telemetry.EventCounts{{Origin: telemetry.OriginReal}}
	}
	s.telemetryMu.RLock()
	defer s.telemetryMu.RUnlock()

	origins := make([]telemetry.Origin, 0, len(s.telemetryCounters))
	for origin := range s.telemetryCounters {
		origins = append(origins, origin)
	}
	sort.Slice(origins, func(i, j int) bool {
		if origins[i] == telemetry.OriginReal {
			return true
		}
		if origins[j] == telemetry.OriginReal {
			return false
		}
		if origins[i] == telemetry.OriginDemo {
			return true
		}
		if origins[j] == telemetry.OriginDemo {
			return false
		}
		return origins[i] < origins[j]
	})

	out := make([]telemetry.EventCounts, 0, len(origins))
	for _, origin := range origins {
		counters := s.telemetryCounters[origin]
		classes := make(map[telemetry.EventClass]uint64, len(eventClasses))
		for i, class := range eventClasses {
			classes[class] = counters.classes[i].Load()
		}
		out = append(out, telemetry.EventCounts{
			Origin:  origin,
			Total:   counters.total.Load(),
			Classes: classes,
		})
	}
	return out
}
