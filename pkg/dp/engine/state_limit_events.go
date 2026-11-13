// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"time"

	"github.com/tonylturner/containd/pkg/dp/events"
)

// publishStateLimitTransitions runs only in the joined housekeeping worker.
// It must not take lifecycleMu: retirement holds it while joining this worker.
// No owners are replaced until the worker has stopped, and all owner locks are
// released before any event is published.
func (e *Engine) publishStateLimitTransitions() {
	transitions := e.ledger.TakeTransitions()
	if len(transitions) == 0 {
		return
	}
	snapshot := e.stateLimitsSnapshot()
	for _, tr := range transitions {
		for _, st := range snapshot.Tables {
			if st.Table == tr.Table {
				e.eventStore.Append(events.Event{Kind: "dataplane.state_limit", Timestamp: time.Now().UTC(), Attributes: map[string]any{
					"table": string(tr.Table), "reason": string(tr.Reason), "mode": string(tr.Mode), "limit": st.Limit,
				}})
				break
			}
		}
	}
}
