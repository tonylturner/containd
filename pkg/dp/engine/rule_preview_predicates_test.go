// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

const previewOpener = "10.60.60.10"

func previewL4Event(src string, at time.Time) events.Event {
	return events.Event{Proto: "tcp", Kind: "flow", SrcIP: src, DstIP: "10.30.30.30",
		SrcPort: 40000, DstPort: 22, Transport: "tcp", Timestamp: at}
}

func previewModbusEvent(src string, at time.Time) events.Event {
	key := flow.Key{SrcIP: net.ParseIP(src), DstIP: net.ParseIP("10.30.30.30"),
		SrcPort: 40000, DstPort: 502, Proto: 6, Dir: flow.DirForward}
	return events.Event{FlowID: key.Hash(), Proto: "modbus", Kind: "request",
		SrcIP: key.SrcIP.String(), DstIP: key.DstIP.String(), SrcPort: key.SrcPort, DstPort: key.DstPort,
		Transport: "tcp", Timestamp: at,
		Attributes: map[string]any{"function_code": uint8(3), "is_write": false, "unit_id": uint8(1)}}
}

// TestPreviewRulePredicates checks that the rule impact preview evaluates
// schedules at each event's time and identities from the running bindings,
// for rules nftables decides and rules queued to the engine alike.
func TestPreviewRulePredicates(t *testing.T) {
	inWindow := time.Date(2026, 10, 24, 3, 0, 0, 0, time.UTC) // Saturday
	outOfWindow := inWindow.Add(9 * time.Hour)
	window := rules.SchedulePredicate{DaysOfWeek: []string{"Saturday"}, StartTime: "02:00", EndTime: "06:00"}
	l4 := rules.Entry{ID: "candidate", Protocols: []rules.Protocol{{Name: "tcp", Port: "22"}}}
	modbus := rules.Entry{ID: "candidate", Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
		ICS: rules.ICSPredicate{Protocol: "modbus"}}
	for _, tc := range []struct {
		name    string
		entry   rules.Entry
		queueID int
		event   func(string, time.Time) events.Event
	}{
		{"L4", l4, 207, previewL4Event},
		{"queued ICS", modbus, 207, previewModbusEvent},
		{"unqueued ICS", modbus, 0, previewModbusEvent},
	} {
		for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
			t.Run(tc.name+" "+string(action), func(t *testing.T) {
				entry := tc.entry
				entry.Action = action
				entry.Schedule = window
				got := previewWithQueue(tc.queueID, nil, entry, tc.event(previewOpener, inWindow), tc.event(previewOpener, outOfWindow))
				if got.MatchCount != 1 || got.TotalEvents != 2 || len(got.Warnings) != 0 {
					t.Fatalf("schedule preview = %+v, want the in-window event only", got)
				}

				entry.Schedule = rules.SchedulePredicate{}
				entry.Identities = []string{"operators"}
				bound := []rules.IdentityBinding{{IP: previewOpener, Identities: []string{"engineers", "operators"}}}
				got = previewWithQueue(tc.queueID, bound, entry, tc.event(previewOpener, inWindow), tc.event("10.60.60.11", inWindow))
				if got.MatchCount != 1 || len(got.Warnings) != 0 {
					t.Fatalf("identity preview = %+v, want the bound opener's event only", got)
				}
				got = previewWithQueue(tc.queueID, nil, entry, tc.event(previewOpener, inWindow))
				if got.MatchCount != 0 || len(got.Warnings) != 1 || got.Warnings[0].Predicate != enforce.PredicateIdentity {
					t.Fatalf("unbound identity preview = %+v, want no match and one identity warning", got)
				}
			})
		}
	}
}

func previewWithQueue(queueID int, bindings []rules.IdentityBinding, entry rules.Entry, evs ...events.Event) PreviewRuleResponse {
	e := &Engine{eventStore: events.NewStore(10)}
	if queueID > 0 {
		e.compiler = enforce.NewCompilerWithSettings(enforce.CompilerSettings{NFQueueGroup: uint16(queueID)}, nil)
	}
	e.ruleSnap.Store(&rules.Snapshot{IdentityBindings: bindings})
	for _, ev := range evs {
		e.eventStore.Append(ev)
	}
	return e.previewRule(entry, previewZoneResolver)
}
