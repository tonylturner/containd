// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// replyPredicateParity uses a real reverse flow orientation and a DENY
// default. An unmatched reply must pass live, without counting in preview.
func replyPredicateParity(t *testing.T, proto string, attrs map[string]any, entry rules.Entry, wantMatch, wantDeny bool) []rules.EvalContext {
	t.Helper()
	ev := predicateEvent(proto, attrs)
	key := (flow.Key{SrcIP: net.ParseIP(ev.SrcIP), DstIP: net.ParseIP(ev.DstIP), SrcPort: ev.SrcPort, DstPort: ev.DstPort, Proto: 6}).Reversed()
	ev.FlowID, ev.Kind = key.Hash(), eventfields.KindResponse
	ev.SrcIP, ev.DstIP, ev.SrcPort, ev.DstPort = key.SrcIP.String(), key.DstIP.String(), key.SrcPort, key.DstPort
	snap := &rules.Snapshot{DPIMode: "enforce", Default: rules.ActionDeny, Firewall: []rules.Entry{entry}}
	e := &Engine{dpiMode: "enforce", eventStore: events.NewStore(10)}
	e.ruleSnap.Store(snap)
	encoded, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var retained events.Event
	if err := json.Unmarshal(encoded, &retained); err != nil {
		t.Fatal(err)
	}
	e.eventStore.Append(retained)
	preview := e.previewRule(entry, previewZoneResolver)
	count := 0
	if wantMatch {
		count = 1
	}
	if preview.MatchCount != count || len(preview.SampleMatches) != count || preview.TotalEvents != 1 {
		t.Fatalf("preview=%+v, want match=%v", preview, wantMatch)
	}
	state := &flow.State{Key: key}
	pkt := &dpi.ParsedPacket{Proto: "tcp", SrcPort: key.SrcPort, DstPort: key.DstPort}
	decoded := dpi.Event{Proto: proto, Kind: eventfields.KindResponse, Attributes: attrs}
	v, _, denied := e.enforceDPIEvents(state, pkt, []dpi.Event{decoded}, false)
	if denied != wantDeny || v.Denies() != wantDeny {
		t.Fatalf("live=%+v denied=%v, want %v", v, denied, wantDeny)
	}
	return evalContextsFromDPIEvent(snap, state, pkt, decoded, "", "")
}

func TestCIPResponsesHaveOnlyMessageFactsLiveAndPreview(t *testing.T) {
	for _, tc := range []struct {
		name       string
		service    uint8
		incomplete bool
		target     string
	}{
		{"complete", 0x0e, false, ""},
		{"retained-unknown", 0x0e, false, "unknown"},
		{"incomplete-MSP", 0x0a, true, ""},
		{"retained-incomplete-MSP-unknown", 0x0a, true, "unknown"},
		{"retained-logical", 0x11, true, "logical"},
		{"retained-symbolic", 0x55, true, "symbolic"},
	} {
		attrs := map[string]any{eventfields.KeyFunctionCode: tc.service}
		if tc.target != "" {
			// Retained metadata must not invent request targets on a response,
			// even if the old event also contains apparently decoded selectors.
			attrs[eventfields.KeyCIPTarget] = tc.target
			attrs[eventfields.KeyObjectClass] = uint16(0x6b)
			attrs[eventfields.KeyInstanceID] = uint16(1)
			attrs[eventfields.KeyAttributeID] = uint16(3)
			attrs[eventfields.KeyCIPSymbol] = []string{"Pump", "Speed"}
		}
		if tc.incomplete {
			attrs[eventfields.KeyCoverageIncomplete] = true
		}
		for form, a := range decodertest.Forms(t, attrs) {
			for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
				for _, p := range []rules.ICSPredicate{
					{Protocol: "cip", ObjectClasses: []uint16{0x6b}},
					{Protocol: "cip", Instances: []uint16{1}},
					{Protocol: "cip", Attributes: []uint16{3}},
					{Protocol: "cip", Tags: []string{"Pump"}},
				} {
					t.Run(fmt.Sprintf("%s/%s/%s/%+v", tc.name, form, action, p), func(t *testing.T) {
						contexts := replyPredicateParity(t, "cip", a, rules.Entry{ID: "candidate", Action: action, ICS: p}, false, false)
						want := rules.ICSContext{Protocol: "cip", FunctionCode: tc.service, HasFunctionCode: true, Direction: "response"}
						if len(contexts) != 1 || !reflect.DeepEqual(*contexts[0].ICS, want) {
							t.Fatalf("response contexts=%+v, want message facts %+v", contexts, want)
						}
					})
				}
				t.Run(fmt.Sprintf("%s/%s/%s/message-only", tc.name, form, action), func(t *testing.T) {
					// Even an incomplete MSP reply retains one evaluable context:
					// explicit message-level DENYs still work, including FC 0x0a.
					p := rules.ICSPredicate{Protocol: "cip", FunctionCode: []uint8{tc.service}, Direction: "response"}
					replyPredicateParity(t, "cip", a, rules.Entry{ID: "candidate", Action: action, ICS: p}, true, action == rules.ActionDeny)
				})
			}
		}
	}
}

func TestDNP3ResponseObjectsStillDecideLiveAndPreview(t *testing.T) {
	attrs := predicateAttrs("dnp3")
	attrs[eventfields.KeyDirection] = "outstation"
	attrs["source_address"], attrs["destination_address"] = uint16(10), uint16(1)
	attrs[eventfields.KeyFunctionCode] = uint8(0x81)
	attrs[eventfields.KeyCoverageIncomplete] = true
	for form, a := range decodertest.Forms(t, attrs) {
		t.Run(form, func(t *testing.T) {
			p := rules.ICSPredicate{Protocol: "dnp3", Groups: []int{30}, Masters: []uint16{1}, Outstations: []uint16{10}}
			contexts := replyPredicateParity(t, "dnp3", a, rules.Entry{ID: "candidate", Action: rules.ActionDeny, ICS: p}, true, true)
			if len(contexts) != 2 || contexts[0].ICS.Group == nil || *contexts[0].ICS.Group != 30 || !contexts[1].ICS.ObjectUnknown {
				t.Fatalf("DNP3 reply lost object/coverage: %+v", contexts)
			}
		})
	}
}
