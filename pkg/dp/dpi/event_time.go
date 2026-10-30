// SPDX-License-Identifier: Apache-2.0

package dpi

import (
	"errors"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

// eventTime selects capture time, including when capture time moves backwards.
// A flow not yet inspected can supply its immutable creation time. Never read
// State.LastSeen here: capture workers update it under a different lock.
// Only callers without capture metadata need the wall-clock default.
func eventTime(state *flow.State, pkt *ParsedPacket) time.Time {
	if pkt != nil && !pkt.Timestamp.IsZero() {
		return pkt.Timestamp
	}
	if pkt == nil && state != nil && !state.FirstSeen.IsZero() {
		return state.FirstSeen
	}
	return time.Now().UTC()
}

func stampEvents(events []Event, at time.Time) {
	for i := range events {
		events[i].Timestamp = at
	}
}

func stampResult(res *InspectResult, at time.Time) {
	stampEvents(res.Events, at)
	for i := range res.Frames {
		stampEvents(res.Frames[i].Events, at)
	}
	if len(res.Events) > 0 && res.Err != nil {
		var fe *FrameError
		if errors.As(res.Err, &fe) && fe.Event.Kind != "" {
			fe.Event.Timestamp = at
		}
	}
}
