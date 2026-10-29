// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"net"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestCIPSessionEventsDoNotMatchObjectSelectors(t *testing.T) {
	for _, name := range []string{"RegisterSession", "ListIdentity", "SendRRData without data item", "implicit I/O"} {
		t.Run(name, func(t *testing.T) {
			attrs := map[string]any{
				// Retained object metadata must not turn a message-only event
				// into an operation or unknown-object coverage.
				eventfields.KeyCIPTarget:   "unknown",
				eventfields.KeyObjectClass: uint16(4),
				eventfields.KeyInstanceID:  uint16(1),
				eventfields.KeyAttributeID: uint16(3),
			}
			ev := predicateEvent("cip", attrs)
			ev.Kind = "session"
			for _, selector := range []struct {
				name      string
				predicate rules.ICSPredicate
			}{
				{name: "class", predicate: rules.ICSPredicate{Protocol: "cip", ObjectClasses: []uint16{4}}},
				{name: "instance", predicate: rules.ICSPredicate{Protocol: "cip", Instances: []uint16{1}}},
				{name: "attribute", predicate: rules.ICSPredicate{Protocol: "cip", Attributes: []uint16{3}}},
				{name: "tag", predicate: rules.ICSPredicate{Protocol: "cip", Tags: []string{"Pump"}}},
			} {
				t.Run(selector.name, func(t *testing.T) {
					assertPredicateParity(t,
						rules.Entry{ID: "object-deny", Action: rules.ActionDeny, ICS: selector.predicate},
						ev, ics.Tolerant, false, false)
				})
			}
			contexts := icsContextsFromDPIEvent(stateForPredicateEvent(ev), dpi.Event{
				Proto: ev.Proto, Kind: ev.Kind, Attributes: ev.Attributes,
			}, nil)
			if len(contexts) != 1 || contexts[0].ObjectUnknown || contexts[0].InstanceUnknown || contexts[0].AttributeUnknown ||
				contexts[0].HasObjectClass || contexts[0].Instance != nil || contexts[0].Attribute != nil || contexts[0].Symbol != nil {
				t.Fatalf("session event gained CIP object facts: %+v", contexts)
			}
		})
	}
}

func TestCIPOperationAttributeSelectorsRemainFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name        string
		service     uint8
		attribute   *uint16
		wantMatch   bool
		wantUnknown bool
	}{
		{name: "Get Attributes All", service: 0x01, wantMatch: true, wantUnknown: true},
		{name: "Get Attribute Single attribute 3", service: 0x0e, attribute: uint16Pointer(3), wantMatch: true},
		{name: "Get Attribute Single attribute 4", service: 0x0e, attribute: uint16Pointer(4)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := predicateAttrs("cip")
			attrs[eventfields.KeyFunctionCode] = tc.service
			if tc.attribute == nil {
				delete(attrs, eventfields.KeyAttributeID)
			} else {
				attrs[eventfields.KeyAttributeID] = *tc.attribute
			}
			assertPredicateParity(t,
				rules.Entry{ID: "attribute-deny", Action: rules.ActionDeny, ICS: rules.ICSPredicate{Protocol: "cip", Attributes: []uint16{3}}},
				predicateEvent("cip", attrs), ics.Tolerant, tc.wantMatch, tc.wantMatch)
			ev := predicateEvent("cip", attrs)
			contexts := icsContextsFromDPIEvent(stateForPredicateEvent(ev), dpi.Event{
				Proto: ev.Proto, Kind: ev.Kind, Attributes: ev.Attributes,
			}, nil)
			if len(contexts) != 1 || contexts[0].AttributeUnknown != tc.wantUnknown {
				t.Fatalf("operation contexts=%+v, want AttributeUnknown=%v", contexts, tc.wantUnknown)
			}
		})
	}
}

func TestCIPUnreadableOperationsUseCoverageForObjectSelectors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		attrs map[string]any
	}{
		{
			name: "truncated selected CIP message",
			attrs: map[string]any{
				eventfields.KeyConformance:        []string{"cip.message_short"},
				eventfields.KeyCoverageIncomplete: true,
			},
		},
		{
			name: "unknown command with payload",
			attrs: map[string]any{
				eventfields.KeyUndecoded:          []string{"cip.encapsulation_payload_unsupported"},
				eventfields.KeyCoverageIncomplete: true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := predicateEvent("cip", tc.attrs)
			ev.Kind = "session"
			contexts := icsContextsFromDPIEvent(stateForPredicateEvent(ev), dpi.Event{
				Proto: ev.Proto, Kind: ev.Kind, Attributes: ev.Attributes,
			}, nil)
			if len(contexts) != 2 || contexts[0].ObjectUnknown || contexts[0].AttributeUnknown || !contexts[1].ObjectUnknown ||
				contexts[1].HasObjectClass || contexts[1].Instance != nil || contexts[1].Attribute != nil || contexts[1].Symbol != nil {
				t.Fatalf("unreadable operation contexts=%+v", contexts)
			}

			for _, action := range []rules.Action{rules.ActionDeny, rules.ActionAllow} {
				matches := action == rules.ActionDeny
				assertPredicateParity(t,
					rules.Entry{ID: "class-selector", Action: action, ICS: rules.ICSPredicate{Protocol: "cip", ObjectClasses: []uint16{4}}},
					ev, ics.Tolerant, matches, true)
			}
		})
	}
}

func stateForPredicateEvent(ev events.Event) *flow.State {
	return &flow.State{Key: flow.Key{
		SrcIP: net.ParseIP(ev.SrcIP), DstIP: net.ParseIP(ev.DstIP),
		SrcPort: ev.SrcPort, DstPort: ev.DstPort, Proto: 6,
	}}
}

func uint16Pointer(v uint16) *uint16 {
	return &v
}
