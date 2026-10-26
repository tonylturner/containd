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

// TestPreviewRuleUnenforcedPredicates checks that the rule impact preview
// resolves identity and schedule predicates the way the applied ruleset does:
// a scheduled rule nftables decides ignores its window, and only rules queued
// to the engine evaluate it.
func TestPreviewRuleUnenforcedPredicates(t *testing.T) {
	inWindow := time.Date(2026, 10, 24, 3, 0, 0, 0, time.UTC) // Saturday
	outOfWindow := inWindow.Add(9 * time.Hour)
	window := rules.SchedulePredicate{DaysOfWeek: []string{"Saturday"}, StartTime: "02:00", EndTime: "06:00"}
	l4Event := func(at time.Time) events.Event {
		return events.Event{Proto: "tcp", Kind: "flow", SrcIP: "10.60.60.10", DstIP: "10.30.30.30",
			SrcPort: 40000, DstPort: 22, Transport: "tcp", Timestamp: at}
	}
	modbusEvent := func(at time.Time) events.Event {
		key := flow.Key{SrcIP: net.ParseIP("10.60.60.10"), DstIP: net.ParseIP("10.30.30.30"),
			SrcPort: 40000, DstPort: 502, Proto: 6, Dir: flow.DirForward}
		return events.Event{FlowID: key.Hash(), Proto: "modbus", Kind: "request",
			SrcIP: key.SrcIP.String(), DstIP: key.DstIP.String(), SrcPort: key.SrcPort, DstPort: key.DstPort,
			Transport: "tcp", Timestamp: at,
			Attributes: map[string]any{"function_code": uint8(3), "is_write": false, "unit_id": uint8(1)}}
	}
	l4 := rules.Entry{ID: "candidate", Protocols: []rules.Protocol{{Name: "tcp", Port: "22"}}}
	modbus := rules.Entry{ID: "candidate", Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
		ICS: rules.ICSPredicate{Protocol: "modbus"}}
	for _, tc := range []struct {
		name    string
		entry   rules.Entry
		action  rules.Action
		queueID int
		event   func(time.Time) events.Event
		want    int // matches among one in-window and one out-of-window event
	}{
		{"scheduled L4 ALLOW is inactive", l4, rules.ActionAllow, 207, l4Event, 0},
		{"scheduled L4 DENY ignores its window", l4, rules.ActionDeny, 207, l4Event, 2},
		{"queued scheduled ICS ALLOW evaluates its window", modbus, rules.ActionAllow, 207, modbusEvent, 1},
		{"queued scheduled ICS DENY evaluates its window", modbus, rules.ActionDeny, 207, modbusEvent, 1},
		{"unqueued scheduled ICS ALLOW is inactive", modbus, rules.ActionAllow, 0, modbusEvent, 0},
		{"unqueued scheduled ICS DENY ignores its window", modbus, rules.ActionDeny, 0, modbusEvent, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := tc.entry
			entry.Action = tc.action
			entry.Schedule = window
			got := previewWithQueue(tc.queueID, entry, tc.event(inWindow), tc.event(outOfWindow))
			if got.MatchCount != tc.want || got.TotalEvents != 2 {
				t.Fatalf("preview = %+v, want %d matches", got, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		action rules.Action
		want   int
	}{{rules.ActionAllow, 0}, {rules.ActionDeny, 2}} {
		t.Run("identity "+string(tc.action), func(t *testing.T) {
			entry := modbus
			entry.Action = tc.action
			entry.Identities = []string{"operators"}
			got := previewWithQueue(207, entry, modbusEvent(inWindow), modbusEvent(outOfWindow))
			if got.MatchCount != tc.want {
				t.Fatalf("preview = %+v, want %d matches", got, tc.want)
			}
		})
	}
}

func previewWithQueue(queueID int, entry rules.Entry, evs ...events.Event) PreviewRuleResponse {
	e := &Engine{eventStore: events.NewStore(10)}
	if queueID > 0 {
		e.compiler = enforce.NewCompilerWithSettings(enforce.CompilerSettings{NFQueueGroup: uint16(queueID)}, nil)
	}
	e.ruleSnap.Store(&rules.Snapshot{})
	for _, ev := range evs {
		e.eventStore.Append(ev)
	}
	return e.previewRule(entry, previewZoneResolver)
}
