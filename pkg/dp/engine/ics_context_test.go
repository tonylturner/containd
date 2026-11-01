// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func dnpHeader(group, variation uint8, low, high uint32) dnp3.ObjectHeader {
	return dnp3.ObjectHeader{Group: group, Variation: variation, HasVariation: true, Qualifier: 0, HasQualifier: true, HasCount: true, Count: uint64(high) - uint64(low) + 1, Start: &low, Stop: &high}
}

func predicateAttrs(proto string) map[string]any {
	switch proto {
	case "dnp3":
		return map[string]any{
			"function_code": uint8(1), "is_write": false, "direction": "master", "source_address": uint16(1), "destination_address": uint16(10),
			"objects": []dnp3.ObjectHeader{dnpHeader(30, 1, 100, 101)},
		}
	case "cip":
		return map[string]any{
			"function_code": uint8(0x0e), "is_write": false,
			eventfields.KeyCIPTarget: "logical", eventfields.KeyObjectClass: uint16(4), eventfields.KeyInstanceID: uint16(1), eventfields.KeyAttributeID: uint16(3),
		}
	case "iec104":
		return map[string]any{
			"apci_type": "I", "direction": "request", "class": "control", "type_id": uint8(45), "ca": uint16(1), "ioa": uint32(100),
			"cause": uint8(6), "originator": uint8(0), "cot_negative": false, "cot_test": false, "select": true,
		}
	default:
		panic("unsupported fixture protocol: " + proto)
	}
}

func predicateEvent(proto string, attrs map[string]any) events.Event {
	ports := map[string]uint16{"dnp3": 20000, "cip": 44818, "iec104": 2404}
	key := flow.Key{SrcIP: net.ParseIP("10.60.60.10"), DstIP: net.ParseIP("10.30.30.30"), SrcPort: 40000, DstPort: ports[proto], Proto: 6}
	return events.Event{FlowID: key.Hash(), Proto: proto, Kind: "request", SrcIP: key.SrcIP.String(), DstIP: key.DstIP.String(), SrcPort: key.SrcPort, DstPort: key.DstPort, Transport: "tcp", Timestamp: time.Unix(1800000000, 0), Attributes: attrs}
}

// assertPredicateParity drives the live entry point and retained-event JSON
// preview independently. A candidate is isolated from other rules in both.
func assertPredicateParity(t *testing.T, entry rules.Entry, ev events.Event, parsing ics.Parsing, wantMatch, wantDenied bool) rules.EvalContext {
	t.Helper()
	if entry.ID == "" {
		entry.ID = "candidate"
	}
	fallback := rules.ActionAllow
	if entry.Action == rules.ActionAllow {
		fallback = rules.ActionDeny
	}
	snap := &rules.Snapshot{DPIMode: "enforce", Default: fallback, Firewall: []rules.Entry{entry}}
	e := &Engine{eventStore: events.NewStore(100), dpiMode: "enforce"}
	e.ruleSnap.Store(snap)
	e.SetICSParsing(map[string]string{ev.Proto: string(parsing)})
	encoded, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var retained events.Event
	if err := json.Unmarshal(encoded, &retained); err != nil {
		t.Fatal(err)
	}
	e.eventStore.Append(retained)
	preview := e.previewRule(PreviewRuleRequest{Entry: entry}, previewZoneResolver)
	wantCount := 0
	if wantMatch {
		wantCount = 1
	}
	if preview.MatchCount != wantCount || preview.TotalEvents != 1 || len(preview.SampleMatches) != wantCount {
		t.Fatalf("preview=%+v, want match=%v", preview, wantMatch)
	}
	decoded := dpi.Event{Proto: ev.Proto, Kind: ev.Kind, Attributes: ev.Attributes, Timestamp: ev.Timestamp, FlowID: ev.FlowID}
	if ev.Proto == iecProtocol {
		table := newIECTable("enforce", &zoneCache{})
		table.policy, table.parsing = newRulesPolicy(snap), parsing
		client, _ := addrPort(net.ParseIP(ev.SrcIP), ev.SrcPort)
		server, _ := addrPort(net.ParseIP(ev.DstIP), ev.DstPort)
		session := &iecSession{mode: "enforce", ctx: iecSessionContext(snap, client, server, previewZoneResolver)}
		decision := table.decideLocked(session, decoded)
		if (decision.ruleID == entry.ID) != wantMatch {
			t.Fatalf("live IEC rule match=%+v, want matched=%v", decision, wantMatch)
		}
		if decision.enforced() != wantDenied {
			t.Fatalf("live IEC=%+v, want denied=%v", decision, wantDenied)
		}
		return rules.EvalContext{}
	}
	state := &flow.State{Key: flow.Key{SrcIP: net.ParseIP(ev.SrcIP), DstIP: net.ParseIP(ev.DstIP), SrcPort: ev.SrcPort, DstPort: ev.DstPort, Proto: 6}}
	pkt := &dpi.ParsedPacket{Proto: ev.Transport, SrcPort: ev.SrcPort, DstPort: ev.DstPort}
	v, ctx, denied := e.enforceDPIEvents(state, pkt, []dpi.Event{decoded}, false)
	if denied != wantDenied || v.Denies() != wantDenied {
		t.Fatalf("live=%+v context=%+v, want denied=%v", v, ctx.ICS, wantDenied)
	}
	return ctx
}

// Every pair differs in only the selected field, not its access class,
// function, stations, connection or other object fields.
func TestICSObjectPredicatePairsLiveAndPreview(t *testing.T) {
	cases := []struct {
		name   string
		p      rules.ICSPredicate
		change func(map[string]any)
	}{
		{"master", rules.ICSPredicate{Protocol: "dnp3", Masters: []uint16{1}}, func(a map[string]any) { a["source_address"] = uint16(2) }},
		{"outstation", rules.ICSPredicate{Protocol: "dnp3", Outstations: []uint16{10}}, func(a map[string]any) { a["destination_address"] = uint16(11) }},
		{"group", rules.ICSPredicate{Protocol: "dnp3", Groups: []int{30}}, func(a map[string]any) { a["objects"].([]dnp3.ObjectHeader)[0].Group = 31 }},
		{"variation", rules.ICSPredicate{Protocol: "dnp3", Variations: []int{1}}, func(a map[string]any) { a["objects"].([]dnp3.ObjectHeader)[0].Variation = 2 }},
		{"point", rules.ICSPredicate{Protocol: "dnp3", Groups: []int{30}, Addresses: []string{"100-101"}}, func(a map[string]any) { a["objects"] = []dnp3.ObjectHeader{dnpHeader(30, 1, 102, 103)} }},
		{"class", rules.ICSPredicate{Protocol: "cip", ObjectClasses: []uint16{4}}, func(a map[string]any) { a[eventfields.KeyObjectClass] = uint16(5) }},
		{"instance", rules.ICSPredicate{Protocol: "cip", Instances: []uint16{1}}, func(a map[string]any) { a[eventfields.KeyInstanceID] = uint16(2) }},
		{"attribute", rules.ICSPredicate{Protocol: "cip", Attributes: []uint16{3}}, func(a map[string]any) { a[eventfields.KeyAttributeID] = uint16(4) }},
		{"tag", rules.ICSPredicate{Protocol: "cip", Tags: []string{"Program:Main.Pump"}}, func(a map[string]any) { a[eventfields.KeyCIPSymbol] = []string{"Program:Main", "Valve", "Speed"} }},
		{"COT", rules.ICSPredicate{Protocol: "iec104", COT: []int{6}}, func(a map[string]any) { a["cause"] = uint8(7) }},
		{"originator-zero", rules.ICSPredicate{Protocol: "iec104", Originators: []int{0}}, func(a map[string]any) { a["originator"] = uint8(1) }},
		{"P-N-false", rules.ICSPredicate{Protocol: "iec104", Negative: boolPointer(false)}, func(a map[string]any) { a["cot_negative"] = true }},
		{"T-false", rules.ICSPredicate{Protocol: "iec104", Test: boolPointer(false)}, func(a map[string]any) { a["cot_test"] = true }},
		{"select", rules.ICSPredicate{Protocol: "iec104", SelectExecute: "select"}, func(a map[string]any) { a["select"] = false }},
		{"execute", rules.ICSPredicate{Protocol: "iec104", SelectExecute: "execute"}, func(a map[string]any) { a["select"] = true }},
	}
	for _, tc := range cases {
		for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
			t.Run(tc.name+"/"+string(action), func(t *testing.T) {
				entry := rules.Entry{ID: "candidate", Action: action, ICS: tc.p}
				for _, matches := range []bool{true, false} {
					attrs := predicateAttrs(tc.p.Protocol)
					if tc.name == "tag" {
						attrs = map[string]any{"function_code": uint8(0x4c), "is_write": false, eventfields.KeyCIPTarget: "symbolic", eventfields.KeyCIPSymbol: []string{"Program:Main", "pump", "Speed"}}
					}
					if tc.name == "execute" {
						attrs["select"] = false
					}
					if !matches {
						tc.change(attrs)
					}
					for form, a := range decodertest.Forms(t, attrs) {
						t.Run(fmt.Sprintf("%v/%s", matches, form), func(t *testing.T) {
							denied := matches == (action == rules.ActionDeny)
							// The IEC envelope always defaults to DENY, unlike
							// generic ICS. ALLOW pairs change the verdict;
							// DENY pairs also assert rule vs default identity.
							if tc.p.Protocol == iecProtocol && action == rules.ActionDeny {
								denied = true
							}
							assertPredicateParity(t, entry, predicateEvent(tc.p.Protocol, a), ics.Tolerant, matches, denied)
						})
					}
				}
			})
		}
	}
}

func boolPointer(v bool) *bool { return &v }

func TestDNP3PerHeaderDenialAndIndependentAllows(t *testing.T) {
	attrs := predicateAttrs("dnp3")
	attrs["objects"] = []dnp3.ObjectHeader{dnpHeader(30, 1, 100, 101), dnpHeader(40, 2, 200, 201), dnpHeader(50, 1, 300, 301)}
	ev := predicateEvent("dnp3", attrs)
	for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
		entry := rules.Entry{ID: "candidate", Action: action, ICS: rules.ICSPredicate{Protocol: "dnp3", Groups: []int{30}}}
		matches := action == rules.ActionDeny
		ctx := assertPredicateParity(t, entry, ev, ics.Tolerant, matches, true)
		wantGroup := uint8(30)
		if action == rules.ActionAllow {
			wantGroup = 40
		}
		if ctx.ICS == nil || ctx.ICS.Group == nil || *ctx.ICS.Group != wantGroup {
			t.Fatalf("first denied context=%+v, want group %d", ctx.ICS, wantGroup)
		}
	}
	// Different ALLOW rules may cover different headers. No rule is
	// required to cover the complete message by itself.
	entries := []rules.Entry{}
	for _, g := range []int{30, 40, 50} {
		entries = append(entries, rules.Entry{ID: fmt.Sprint(g), Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: "dnp3", Groups: []int{g}}})
	}
	e := &Engine{dpiMode: "enforce", eventStore: events.NewStore(10)}
	e.ruleSnap.Store(&rules.Snapshot{DPIMode: "enforce", Default: rules.ActionDeny, Firewall: entries})
	state := &flow.State{Key: flow.Key{SrcIP: net.ParseIP(ev.SrcIP), DstIP: net.ParseIP(ev.DstIP), SrcPort: ev.SrcPort, DstPort: ev.DstPort, Proto: 6}}
	if v, _, drop := e.enforceDPIEvents(state, &dpi.ParsedPacket{Proto: "tcp", DstPort: ev.DstPort}, []dpi.Event{{Proto: ev.Proto, Kind: ev.Kind, Attributes: attrs}}, false); drop {
		t.Fatalf("independent allows denied: %+v", v)
	}
	// Multiple matching contexts count as just one retained event.
	entry := rules.Entry{Action: rules.ActionDeny, ICS: rules.ICSPredicate{Protocol: "dnp3", Groups: []int{30, 40, 50}}}
	assertPredicateParity(t, entry, ev, ics.Tolerant, true, true)
}

func TestICSIncompleteCoverageAsymmetry(t *testing.T) {
	for _, proto := range []string{"dnp3", "cip"} {
		for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
			for _, incomplete := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/%v", proto, action, incomplete), func(t *testing.T) {
					attrs := predicateAttrs(proto)
					attrs[eventfields.KeyCoverageIncomplete] = incomplete
					p := rules.ICSPredicate{Protocol: proto, Mode: "enforce"}
					if proto == "dnp3" {
						p.Groups = []int{99}
						if action == rules.ActionAllow {
							p.Groups = []int{30}
						}
					} else {
						p.Instances = []uint16{99}
						if action == rules.ActionAllow {
							p.Instances = []uint16{1}
						}
					}
					// ALLOW succeeds only on complete coverage. DENY of an otherwise
					// nonmatching object succeeds only on incomplete coverage.
					matches := incomplete == (action == rules.ActionDeny)
					ctx := assertPredicateParity(t, rules.Entry{ID: "candidate", Action: action, ICS: p}, predicateEvent(proto, attrs), ics.Tolerant, matches, incomplete)
					if incomplete && (ctx.ICS == nil || !ctx.ICS.ObjectUnknown) {
						t.Fatalf("coverage was not the denied context: %+v", ctx.ICS)
					}
				})
			}
		}
	}
}

func TestCIPMSPWrapperContexts(t *testing.T) {
	for _, incomplete := range []bool{false, true} {
		attrs := map[string]any{"function_code": uint8(0x0a), eventfields.KeyCoverageIncomplete: incomplete, eventfields.KeyCIPTarget: "logical", eventfields.KeyObjectClass: uint16(2)}
		for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
			entry := rules.Entry{Action: action, ICS: rules.ICSPredicate{Protocol: "cip"}}
			assertPredicateParity(t, entry, predicateEvent("cip", attrs), ics.Tolerant, incomplete, incomplete && action == rules.ActionDeny)
		}
	}
}

func TestCIPMSPOperationsJudgeOwnTargets(t *testing.T) {
	wrapper := predicateAttrs("cip")
	wrapper[eventfields.KeyFunctionCode] = uint8(0x0a)
	first, second := predicateAttrs("cip"), predicateAttrs("cip")
	second[eventfields.KeyInstanceID] = uint16(2)
	for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
		instance, fallback := uint16(1), rules.ActionDeny
		if action == rules.ActionDeny {
			instance, fallback = 2, rules.ActionAllow
		}
		entry := rules.Entry{ID: "candidate", Action: action, ICS: rules.ICSPredicate{Protocol: "cip", Instances: []uint16{instance}}}
		e := &Engine{dpiMode: "enforce", eventStore: events.NewStore(100)}
		e.ruleSnap.Store(&rules.Snapshot{DPIMode: "enforce", Default: fallback, Firewall: []rules.Entry{entry}})
		var decoded []dpi.Event
		for i, attrs := range []map[string]any{wrapper, first, second} {
			ev := predicateEvent("cip", attrs)
			ev.Timestamp = ev.Timestamp.Add(time.Duration(i) * time.Second)
			encoded, err := json.Marshal(ev)
			if err != nil {
				t.Fatal(err)
			}
			var retained events.Event
			if err := json.Unmarshal(encoded, &retained); err != nil {
				t.Fatal(err)
			}
			e.eventStore.Append(retained)
			decoded = append(decoded, dpi.Event{Proto: ev.Proto, Kind: ev.Kind, Attributes: attrs})
		}
		preview := e.previewRule(PreviewRuleRequest{Entry: entry}, previewZoneResolver)
		if preview.MatchCount != 1 || preview.TotalEvents != 3 ||
			preview.SampleMatches[0].Attributes[eventfields.KeyInstanceID] != float64(instance) {
			t.Fatalf("preview included wrapper or other operation: %+v", preview)
		}
		state := &flow.State{Key: flow.Key{SrcIP: net.ParseIP("10.60.60.10"), DstIP: net.ParseIP("10.30.30.30"), SrcPort: 40000, DstPort: 44818, Proto: 6}}
		v, ctx, drop := e.enforceDPIEvents(state, &dpi.ParsedPacket{Proto: "tcp", SrcPort: 40000, DstPort: 44818}, decoded, false)
		if !drop || !v.Denies() || ctx.ICS == nil || ctx.ICS.Instance == nil || *ctx.ICS.Instance != 2 {
			t.Fatalf("second operation must deny whole message: %+v %+v", v, ctx.ICS)
		}
	}
}

func TestICSCoverageMessageFacts(t *testing.T) {
	for _, proto := range []string{"dnp3", "cip"} {
		attrs := predicateAttrs(proto)
		attrs[eventfields.KeyCoverageIncomplete] = true
		state := &flow.State{}
		contexts := icsContextsFromDPIEvent(state, dpi.Event{Proto: proto, Attributes: attrs}, nil)
		c := contexts[len(contexts)-1]
		if !c.ObjectUnknown || c.Group != nil || c.Variation != nil || c.Instance != nil || c.Attribute != nil || c.HasObjectClass || c.Symbol != nil || c.Spans != nil {
			t.Fatalf("coverage leaked object facts: %+v", c)
		}
		if proto == "dnp3" {
			if !c.HasFunctionCode || c.FunctionCode != 1 || !c.ReadOnly || c.Master == nil || *c.Master != 1 || c.Outstation == nil || *c.Outstation != 10 {
				t.Fatalf("lost message facts: %+v", c)
			}
		} else if c.HasFunctionCode || c.ReadOnly || c.WriteOnly {
			t.Fatalf("CIP coverage leaked operation facts: %+v", c)
		}
		// ObjectUnknown never bypasses other message selectors.
		p := rules.ICSPredicate{Protocol: proto, FunctionCode: []uint8{99}}
		if proto == "dnp3" {
			p.Groups = []int{30}
		} else {
			p.Tags = []string{"Pump"}
		}
		assertPredicateParity(t, rules.Entry{Action: rules.ActionDeny, ICS: p}, predicateEvent(proto, attrs), ics.Tolerant, false, false)
	}
}

func TestDNP3LinkRolesAndAbsentHeaders(t *testing.T) {
	for _, dir := range []string{"master", "outstation", ""} {
		attrs := predicateAttrs("dnp3")
		attrs["direction"] = dir
		delete(attrs, "objects")
		attrs["object_groups"] = "99"
		c := icsContextsFromDPIEvent(&flow.State{}, dpi.Event{Proto: "dnp3", Attributes: attrs}, nil)
		if len(c) != 1 || c[0].Group != nil || c[0].Variation != nil {
			t.Fatalf("header-zero convenience field used: %+v", c)
		}
		switch dir {
		case "master":
			if *c[0].Master != 1 || *c[0].Outstation != 10 {
				t.Fatalf("master roles %+v", c[0])
			}
		case "outstation":
			if *c[0].Master != 10 || *c[0].Outstation != 1 {
				t.Fatalf("outstation roles %+v", c[0])
			}
		default:
			if c[0].Master != nil || c[0].Outstation != nil {
				t.Fatal("invented link roles")
			}
		}
	}
}

func TestDNP3QualifierSpansRetainedJSON(t *testing.T) {
	for _, q := range []uint8{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x17, 0x28, 0x39, 0x47, 0x5b, 0x67, 0x0a, 0x80} {
		t.Run(fmt.Sprintf("%02x", q), func(t *testing.T) {
			h := dnpHeader(30, 1, 100, 101)
			h.Qualifier = q
			x, y := uint32(100), uint32(101)
			h.Points = []dnp3.Point{{Index: &x}, {Index: &y}}
			attrs := map[string]any{"objects": []dnp3.ObjectHeader{h}}
			unknown := q != 0 && q != 1 && q != 2 && q != 0x17 && q != 0x28 && q != 0x39
			want := []rules.AddressSpan(nil)
			if !unknown {
				want = []rules.AddressSpan{{Low: 100, High: 101}}
				if q > 2 {
					want = []rules.AddressSpan{{Low: 100, High: 100}, {Low: 101, High: 101}}
				}
			}
			for form, a := range decodertest.Forms(t, attrs) {
				c := icsContextsFromDPIEvent(&flow.State{}, dpi.Event{Proto: "dnp3", Attributes: a}, nil)
				if len(c) != 1 || c[0].SpansUnknown != unknown || !reflect.DeepEqual(c[0].Spans, want) {
					t.Fatalf("%s: context=%+v want spans=%v unknown=%v", form, c, want, unknown)
				}
			}
		})
	}
	// The stopped header remains present with unknown spans, and partial
	// indexed points cannot masquerade as complete coverage.
	for _, indexed := range []bool{false, true} {
		attrs := predicateAttrs("dnp3")
		h := dnpHeader(30, 1, 100, 101)
		if indexed {
			h.Qualifier = 0x17
			x := uint32(100)
			h.Points = []dnp3.Point{{Index: &x}}
		}
		attrs["objects"] = []dnp3.ObjectHeader{h}
		attrs[eventfields.KeyCoverageIncomplete] = true
		attrs[eventfields.KeyUndecoded] = []string{"dnp3.object_truncated"}
		for _, a := range decodertest.Forms(t, attrs) {
			c := icsContextsFromDPIEvent(&flow.State{}, dpi.Event{Proto: "dnp3", Attributes: a}, nil)
			if len(c) != 2 || c[0].Group == nil || !c[0].SpansUnknown || !c[1].ObjectUnknown {
				t.Fatalf("stopped header=%+v", c)
			}
		}
	}
}

func TestCIPTargetUnknownAndEnumeration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
		p      rules.ICSPredicate
	}{
		{"unknown target", func(a map[string]any) { a[eventfields.KeyCIPTarget] = "unknown" }, rules.ICSPredicate{Protocol: "cip", Instances: []uint16{1}}},
		{"enumerate instances", func(a map[string]any) { a["function_code"] = uint8(0x11) }, rules.ICSPredicate{Protocol: "cip", Instances: []uint16{1}}},
		{"enumerate symbols", func(a map[string]any) { a["function_code"] = uint8(0x55); a[eventfields.KeyObjectClass] = uint16(0x6b) }, rules.ICSPredicate{Protocol: "cip", Instances: []uint16{1}}},
		{"all attributes", func(a map[string]any) { a["function_code"] = uint8(1) }, rules.ICSPredicate{Protocol: "cip", Attributes: []uint16{3}}},
	} {
		for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
			t.Run(tc.name+"/"+string(action), func(t *testing.T) {
				attrs := predicateAttrs("cip")
				tc.change(attrs)
				matches := action == rules.ActionDeny
				assertPredicateParity(t, rules.Entry{Action: action, ICS: tc.p}, predicateEvent("cip", attrs), ics.Tolerant, matches, true)
			})
		}
	}
	// A logical class 0x6b target is not a symbolic path.
	attrs := predicateAttrs("cip")
	attrs[eventfields.KeyObjectClass] = uint16(0x6b)
	for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
		assertPredicateParity(t, rules.Entry{Action: action, ICS: rules.ICSPredicate{Protocol: "cip", Tags: []string{"Pump"}}}, predicateEvent("cip", attrs), ics.Tolerant, false, action == rules.ActionAllow)
	}
}

func TestIEC104SelectOnlyOnCommandTypes(t *testing.T) {
	for _, id := range []uint8{1, 44, 45, 46, 47, 48, 49, 50, 51, 57, 58, 59, 60, 61, 62, 63, 64, 100} {
		attrs := predicateAttrs("iec104")
		attrs["type_id"] = id
		c := iecContextFromDPIEvent(dpi.Event{Proto: "iec104", Attributes: attrs}, func(map[string]any) bool { return false })
		want := id >= 45 && id <= 50 || id >= 58 && id <= 63
		if (c.IEC104.Select != nil) != want {
			t.Fatalf("type %d select=%v", id, c.IEC104.Select)
		}
	}
	for _, apci := range []string{"S", "U"} {
		attrs := predicateAttrs("iec104")
		attrs["apci_type"] = apci
		c := iecContextFromDPIEvent(dpi.Event{Proto: "iec104", Attributes: attrs}, func(map[string]any) bool { return false }).IEC104
		if c.COT != nil || c.Originator != nil || c.Negative != nil || c.Test != nil || c.Select != nil {
			t.Fatalf("%s has ASDU predicates %+v", apci, c)
		}
	}
	// Missing is not false (including an explicit false predicate).
	for _, key := range []string{"cause", "originator", "cot_negative", "cot_test", "select"} {
		attrs := predicateAttrs("iec104")
		delete(attrs, key)
		p := rules.ICSPredicate{Protocol: "iec104"}
		switch key {
		case "cause":
			p.COT = []int{6}
		case "originator":
			p.Originators = []int{0}
		case "cot_negative":
			p.Negative = boolPointer(false)
		case "cot_test":
			p.Test = boolPointer(false)
		case "select":
			p.SelectExecute = "execute"
		}
		for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
			assertPredicateParity(t, rules.Entry{Action: action, ICS: p}, predicateEvent("iec104", attrs), ics.Tolerant, false, true)
		}
	}
}

func TestICSStrictPreviewActionAware(t *testing.T) {
	for _, proto := range []string{"dnp3", "cip", "iec104"} {
		for _, key := range []string{eventfields.KeyConformance, eventfields.KeyUndecoded} {
			for _, parsing := range []ics.Parsing{ics.Tolerant, ics.Strict} {
				for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
					t.Run(fmt.Sprintf("%s/%s/%s/%s", proto, key, parsing, action), func(t *testing.T) {
						attrs := predicateAttrs(proto)
						attrs[key] = []string{proto + ".finding"}
						p := rules.ICSPredicate{Protocol: proto, Mode: "enforce"}
						if proto == "dnp3" {
							p.Groups = []int{30}
						} else if proto == "cip" {
							p.Instances = []uint16{1}
						} else {
							p.COT = []int{6}
						}
						entry := rules.Entry{ID: "candidate", Action: action, ICS: p}
						matches := parsing != ics.Strict
						assertPredicateParity(t, entry, predicateEvent(proto, attrs), parsing, matches, action == rules.ActionDeny || parsing == ics.Strict)
					})
				}
			}
		}
	}
}

func TestDNP3ConformanceRecordedOnceForMultipleHeaders(t *testing.T) {
	attrs := predicateAttrs("dnp3")
	attrs["objects"] = []dnp3.ObjectHeader{dnpHeader(30, 1, 100, 101), dnpHeader(40, 1, 200, 201)}
	attrs[eventfields.KeyConformance] = []string{"dnp3.finding"}
	state := &flow.State{Key: flow.Key{SrcIP: net.ParseIP("10.60.60.10"), DstIP: net.ParseIP("10.30.30.30"), SrcPort: 40000, DstPort: 20000, Proto: 6}}
	pkt := &dpi.ParsedPacket{Proto: "tcp", SrcPort: 40000, DstPort: 20000}
	e := &Engine{dpiMode: "enforce", eventStore: events.NewStore(100)}
	e.SetICSParsing(map[string]string{"dnp3": "strict"})
	e.ruleSnap.Store(&rules.Snapshot{DPIMode: "enforce", Default: rules.ActionDeny, Firewall: []rules.Entry{{ID: "decoded-deny", Action: rules.ActionDeny, ICS: rules.ICSPredicate{Protocol: "dnp3", Groups: []int{40}}}}})
	v, ctx, drop := e.enforceDPIEvents(state, pkt, []dpi.Event{{Proto: "dnp3", Kind: "request", Attributes: maps.Clone(attrs)}}, false)
	if !drop || v.Reason != reasonNonconformant || ctx.ICS.Group == nil {
		t.Fatalf("strict scope failed to preempt decoded denial: %+v %+v", v, ctx)
	}
	decisions := findingEvents(e, eventfields.KindDecision)
	if len(decisions) != 1 || decisions[0].Attributes["scopeId"] != "decoded-deny" || decisions[0].Attributes[eventfields.KeyRuleID] != nil || decisions[0].Attributes[eventfields.KeyReason] != reasonNonconformant {
		t.Fatalf("conformance decisions=%+v", decisions)
	}
}
