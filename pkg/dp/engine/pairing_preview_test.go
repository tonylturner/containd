// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestDS34ConsumersPairingPreview(t *testing.T) {
	e := &Engine{eventStore: events.NewStore(100).Writer("")}
	entry := rules.Entry{ID: "responses", Action: rules.ActionAllow,
		ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "monitor", Direction: "response", TypeIDs: []int{46}}}
	snap := &rules.Snapshot{DPIMode: "enforce", Firewall: []rules.Entry{entry, entry}}
	e.ruleSnap.Store(snap)
	for i, reason := range []pairReason{pairOK, pairUnpaired, pairExpired, pairAmbiguous, pairUnsupported,
		pairUnknown, pairMismatch, autonomousRequired, sessionRequired, messageTimeout, stateLimit, "unbounded text"} {
		a := map[string]any{"apci_type": "I", "direction": "response", "type_id": uint8(46), "cause": uint8(7),
			"ca": uint16(1), "message_class": "solicited", "pairing_outcome": pairOutcome(reason), "pairing_reason": string(reason)}
		e.eventStore.Append(iecEvent(uint64(i+1), "response", false, a))
	}
	// Pre-upgrade retention has decoded class facts, but no pairing authority.
	e.eventStore.Append(iecEvent(20, "response", false, map[string]any{
		"apci_type": "I", "direction": "response", "type_id": uint8(46), "cause": uint8(7), "ca": uint16(1)}))
	// An outcome without the engine's class stamp is not pairing evidence.
	e.eventStore.Append(iecEvent(22, "response", false, map[string]any{
		"apci_type": "I", "direction": "response", "type_id": uint8(46), "cause": uint8(7), "ca": uint16(1), "pairing_outcome": "paired", "pairing_reason": "paired"}))
	// A different predicate is not part of this preview selection.
	e.eventStore.Append(iecEvent(21, "request", true, map[string]any{
		"apci_type": "I", "direction": "request", "type_id": uint8(46), "cause": uint8(6), "ca": uint16(1)}))
	got := e.PreviewRule(PreviewRuleRequest{Entry: entry})
	want := &PairingPreview{Paired: 1, Unpaired: 4, Expired: 1, Ambiguous: 1, Unsupported: 1, Unknown: 6,
		Reasons: []string{"autonomous_rule_required", "message_timeout", "paired", "pairing_ambiguous", "pairing_expired",
			"pairing_mismatch", "pairing_unknown", "pairing_unsupported", "session_rule_required", "state_limit", "unpaired"}}
	if got.MatchCount != 14 || !reflect.DeepEqual(got.Pairing, want) {
		t.Fatalf("rule preview: %+v pairing=%+v", got, got.Pairing)
	}
	if got := e.PreviewPairing(snap); !reflect.DeepEqual(got, want) {
		t.Fatalf("ruleset pairing counted overlaps: %+v", got)
	}
}

func TestDS34ConsumersEmptyRetentionWarnings(t *testing.T) {
	e := &Engine{eventStore: events.NewStore(10).Writer("")}
	e.ruleSnap.Store(&rules.Snapshot{DPIMode: "enforce"})
	entry := rules.Entry{ID: "old", Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: "dnp3", FunctionCode: []uint8{130}}}
	got := e.PreviewRule(PreviewRuleRequest{Entry: entry})
	if got.MatchCount != 0 || got.TotalEvents != 0 || got.Pairing == nil || got.Pairing.Unknown != 0 {
		t.Fatalf("empty history: %+v", got)
	}
	if len(got.Warnings) == 0 || !strings.Contains(got.Warnings[len(got.Warnings)-1].Message, "messageClass") {
		t.Fatalf("empty history hid cutover warnings: %+v", got.Warnings)
	}
}
