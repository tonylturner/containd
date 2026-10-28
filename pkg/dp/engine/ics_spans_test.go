// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"encoding/hex"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// ADUs captured between a pymodbus client and server.
const (
	aduReadInRange   = "0001000000060103000a0002"                                   // FC 3, 10 count 2
	aduReadCrossing  = "0001000000060103000b0008"                                   // FC 3, 11 count 8
	aduReadReply     = "000100000007010304000b000c"                                 // FC 3 reply, values 11, 12
	aduWriteCrossing = "0001000000170110000b000810038403850386038703880389038a038b" // FC 16, 11 x 8
	aduWriteReply    = "0005000000060110001e0002"                                   // FC 16 reply, 30 count 2
	aduUnknownFC     = "007000000006015a000a0002"                                   // FC 0x5a
	aduShortPDU      = "0073000000020103"                                           // FC 3, no fields
)

func modbusKey(sport uint16, dir flow.Direction) flow.Key {
	key := flow.Key{SrcIP: net.ParseIP("10.245.0.40"), DstIP: net.ParseIP("10.246.0.10"), SrcPort: sport, DstPort: 502, Proto: 6}
	if dir == flow.DirReverse {
		key = key.Reversed()
	}
	return key
}

// decodeModbus decodes one ADU with the production decoder on key.
func decodeModbus(t *testing.T, key flow.Key, aduHex string) (*flow.State, *dpi.ParsedPacket, dpi.Event) {
	t.Helper()
	raw, err := hex.DecodeString(aduHex)
	if err != nil {
		t.Fatal(err)
	}
	state := &flow.State{Key: key}
	pkt := &dpi.ParsedPacket{Proto: "tcp", SrcPort: key.SrcPort, DstPort: key.DstPort, Payload: raw}
	evs, err := modbus.NewDecoder().OnPacket(state, pkt)
	if err != nil || len(evs) != 1 {
		t.Fatalf("decode %s: %d events, %v", aduHex, len(evs), err)
	}
	return state, pkt, evs[0]
}

// The rule context carries the spans the decoded message touches, oriented
// by the connection: a request the decoder could not bound, or labelled a
// reply, has unknown spans; a reply touches only what it echoes.
func TestEvalContextModbusSpans(t *testing.T) {
	cases := []struct {
		name    string
		key     flow.Key
		adu     string
		spans   []rules.AddressSpan
		unknown bool
	}{
		{"in-range read", modbusKey(40000, flow.DirForward), aduReadInRange, []rules.AddressSpan{{Low: 10, High: 11}}, false},
		{"range-crossing read", modbusKey(40000, flow.DirForward), aduReadCrossing, []rules.AddressSpan{{Low: 11, High: 18}}, false},
		{"range-crossing write", modbusKey(40000, flow.DirForward), aduWriteCrossing, []rules.AddressSpan{{Low: 11, High: 18}}, false},
		{"read reply", modbusKey(40000, flow.DirReverse), aduReadReply, nil, false},
		{"write reply", modbusKey(40000, flow.DirReverse), aduWriteReply, []rules.AddressSpan{{Low: 30, High: 31}}, false},
		{"unknown function code", modbusKey(40000, flow.DirForward), aduUnknownFC, nil, true},
		{"short PDU", modbusKey(40000, flow.DirForward), aduShortPDU, nil, true},
		{"request from source port 502", modbusKey(502, flow.DirForward), aduReadCrossing, []rules.AddressSpan{{Low: 11, High: 18}}, false},
	}
	for _, tc := range cases {
		state, pkt, ev := decodeModbus(t, tc.key, tc.adu)
		ctx, ok := evalContextFromDPIEvent(nil, state, pkt, ev, "", "")
		if !ok {
			t.Fatalf("%s: no context", tc.name)
		}
		if !reflect.DeepEqual(ctx.ICS.Spans, tc.spans) || ctx.ICS.SpansUnknown != tc.unknown {
			t.Errorf("%s: spans %v unknown %v, want %v %v", tc.name, ctx.ICS.Spans, ctx.ICS.SpansUnknown, tc.spans, tc.unknown)
		}
	}
}

// Protocols other than Modbus touch the one numeric address their decoder
// emits; a non-numeric address touches none and is not unknown.
func TestEvalContextOtherProtocolAddress(t *testing.T) {
	state := &flow.State{Key: flow.Key{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"), SrcPort: 40000, DstPort: 44818, Proto: 6}}
	pkt := &dpi.ParsedPacket{Proto: "tcp", SrcPort: 40000, DstPort: 44818}
	cases := []struct {
		addr  any
		spans []rules.AddressSpan
	}{
		{uint16(256), []rules.AddressSpan{{Low: 256, High: 256}}},
		{"0x0100", []rules.AddressSpan{{Low: 256, High: 256}}},
		{float64(7), []rules.AddressSpan{{Low: 7, High: 7}}},
		{"0x02/1/1", nil},
		{"1-2", nil},
		{nil, nil},
	}
	for _, tc := range cases {
		attrs := map[string]any{"service_code": uint8(0x0e)}
		if tc.addr != nil {
			attrs["address"] = tc.addr
		}
		ctx, ok := evalContextFromDPIEvent(nil, state, pkt, dpi.Event{Proto: "cip", Kind: "request", Attributes: attrs}, "", "")
		if !ok || !reflect.DeepEqual(ctx.ICS.Spans, tc.spans) || ctx.ICS.SpansUnknown {
			t.Errorf("address %#v: spans %v unknown %v, want %v", tc.addr, ctx.ICS.Spans, ctx.ICS.SpansUnknown, tc.spans)
		}
	}
}

// Inline enforcement of decoded pymodbus ADUs: an ALLOW of 10-11 admits the
// in-range read and not the range-crossing read or write; a DENY of 12-19
// under an ALLOW default drops whatever reaches into it and anything it
// cannot bound.
func TestEnforceModbusRequestSpans(t *testing.T) {
	unit := uint8(1)
	allow := &rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{{
		ID: "allow-10-11", Action: rules.ActionAllow,
		ICS: rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3, 16}, UnitID: &unit, Addresses: []string{"10-11"}},
	}}}
	deny := &rules.Snapshot{Default: rules.ActionAllow, Firewall: []rules.Entry{{
		ID: "deny-12-19", Action: rules.ActionDeny,
		ICS: rules.ICSPredicate{Protocol: "modbus", Addresses: []string{"12-19"}},
	}}}
	cases := []struct {
		snap    *rules.Snapshot
		adu     string
		dropped bool
	}{
		{allow, aduReadInRange, false},
		{allow, aduReadCrossing, true},
		{allow, aduWriteCrossing, true},
		{allow, aduUnknownFC, true},
		{deny, aduReadInRange, false},
		{deny, aduReadCrossing, true},
		{deny, aduWriteCrossing, true},
		{deny, aduUnknownFC, true},
		{deny, aduShortPDU, true},
	}
	for _, tc := range cases {
		e := &Engine{eventStore: events.NewStore(10), dpiMode: "enforce"}
		e.ruleSnap.Store(tc.snap)
		state, pkt, ev := decodeModbus(t, modbusKey(40000, flow.DirForward), tc.adu)
		v, _, enforced := e.enforceDPIEvents(state, pkt, []dpi.Event{ev}, false)
		if dropped := enforced && v.Denies(); dropped != tc.dropped {
			t.Errorf("%s under %s: dropped=%v (%+v), want %v", tc.adu, tc.snap.Firewall[0].ID, dropped, v, tc.dropped)
		}
	}
}

func TestConformanceUnknownSpansCannotMatchAllow(t *testing.T) {
	assertConformanceUnknownSpanMatch(t, rules.ActionAllow, false)
}

func TestConformanceUnknownSpansMatchDenyReset(t *testing.T) {
	for _, action := range []rules.Action{rules.ActionDeny, rules.ActionReset} {
		t.Run(string(action), func(t *testing.T) {
			assertConformanceUnknownSpanMatch(t, action, true)
		})
	}
}

func assertConformanceUnknownSpanMatch(t *testing.T, action rules.Action, wantMatch bool) {
	t.Helper()
	state, pkt, ev := decodeModbus(t, modbusKey(40000, flow.DirForward), aduShortPDU)
	ev.Attributes[eventfields.KeyConformance] = []string{"modbus.truncated_pdu"}
	ctx, ok := evalContextFromDPIEvent(nil, state, pkt, ev, "", "")
	if !ok || !ctx.ICS.HasFunctionCode || ctx.ICS.FunctionCode != 3 || !ctx.ICS.SpansUnknown {
		t.Fatalf("expected decoded FC 3 with unknown address coverage: %+v", ctx.ICS)
	}
	entry := rules.Entry{ID: "address-rule", Action: action,
		ICS: rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}, Addresses: []string{"12-19"}}}
	if got := rules.PreviewMatch(entry, ctx); got != wantMatch {
		t.Fatalf("%s matched=%v, want %v", action, got, wantMatch)
	}
	// Tolerant findings must preserve the address predicate's asymmetry:
	// an unprovable ALLOW falls to default DENY; DENY/RESET overrides ALLOW default.
	defaultAction, wantReason := rules.ActionAllow, reasonRule
	if action == rules.ActionAllow {
		defaultAction, wantReason = rules.ActionDeny, reasonDefault
	}
	e := &Engine{eventStore: events.NewStore(10), dpiMode: "enforce"}
	e.ruleSnap.Store(&rules.Snapshot{Default: defaultAction, Firewall: []rules.Entry{entry}})
	v, _, enforced := e.enforceDPIEvents(state, pkt, []dpi.Event{ev}, false)
	if !enforced || !v.Denies() {
		t.Fatalf("unknown address coverage passed: %+v", v)
	}
	decisions := findingEvents(e, eventfields.KindDecision)
	if len(decisions) != 1 || decisions[0].Attributes[eventfields.KeyReason] != wantReason {
		t.Fatalf("decision=%+v, want reason %s", decisions, wantReason)
	}
}

// Rule preview evaluates stored events through the same context: an ALLOW
// of 10-11 matches the in-range read only, a DENY of 12-19 the crossing one.
func TestPreviewModbusSpans(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	var stored []events.Event
	for _, aduHex := range []string{aduReadInRange, aduReadCrossing} {
		state, pkt, ev := decodeModbus(t, modbusKey(40000, flow.DirForward), aduHex)
		stored = append(stored, events.Event{FlowID: state.Key.Hash(), Proto: ev.Proto, Kind: ev.Kind,
			SrcIP: state.Key.SrcIP.String(), DstIP: state.Key.DstIP.String(), SrcPort: pkt.SrcPort, DstPort: pkt.DstPort,
			Transport: "tcp", Timestamp: at, Attributes: ev.Attributes})
	}
	for _, tc := range []struct {
		action rules.Action
		addrs  string
		want   string
	}{
		{rules.ActionAllow, "10-11", aduReadInRange},
		{rules.ActionDeny, "12-19", aduReadCrossing},
	} {
		entry := rules.Entry{ID: "candidate", Action: tc.action, ICS: rules.ICSPredicate{Protocol: "modbus", Addresses: []string{tc.addrs}}}
		got := previewWithQueue(207, nil, entry, stored...)
		if got.MatchCount != 1 || got.SampleMatches[0].Attributes["raw_hex"] != tc.want {
			t.Errorf("%s %s preview = %+v, want only %s", tc.action, tc.addrs, got, tc.want)
		}
	}
}
