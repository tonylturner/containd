// SPDX-License-Identifier: Apache-2.0
package engine

import (
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"testing"
)

func TestDS34PreviewUnknownFacts(t *testing.T) {
	events := []dpevents.Event{iecEvent(1, "request", true, map[string]any{"apci_type": "I", "direction": "request", "class": "control", "type_id": 46, "ca": 1, "ioa": 2001})}
	rule := `{"id":"cmd","action":"ALLOW","ics":{"protocol":"iec104","mode":"enforce","typeIds":[46]}}`
	if got := previewRule(t, events, rule); got.MatchCount != 0 {
		t.Fatalf("missing cause invented classification: %+v", got)
	}
	events[0].Attributes["cause"] = 6
	if got := previewRule(t, events, rule); got.MatchCount != 1 {
		t.Fatalf("decoded request lost positive match: %+v", got)
	}
}
