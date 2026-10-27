// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package learn

import (
	"encoding/hex"
	"net"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func decodeRequest(t *testing.T, aduHex string) dpi.Event {
	t.Helper()
	raw, err := hex.DecodeString(aduHex)
	if err != nil {
		t.Fatal(err)
	}
	state := &flow.State{Key: flow.Key{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"), SrcPort: 40000, DstPort: 502, Proto: 6}}
	evs, err := modbus.NewDecoder().OnPacket(state, &dpi.ParsedPacket{Payload: raw})
	if err != nil || len(evs) != 1 {
		t.Fatalf("decode %s: %d events, %v", aduHex, len(evs), err)
	}
	return evs[0]
}

func spanContext(ev dpi.Event) rules.EvalContext {
	spans, ok := modbus.AddressSpans(ev.Attributes)
	ics := &rules.ICSContext{Protocol: "modbus", SpansUnknown: !ok}
	for _, sp := range spans {
		ics.Spans = append(ics.Spans, rules.AddressSpan{Low: uint32(sp.First), High: uint32(sp.Last)})
	}
	return rules.EvalContext{ICS: ics}
}

// A learned Modbus rule lists each observed span, not only its start, so
// it keeps admitting every observed request and nothing past it.
func TestLearnedModbusAddressesCoverObservedSpans(t *testing.T) {
	observed := map[string]string{
		"0002000000060103000a0002":                                   "FC 3 read 10 count 2",
		"0001000000170110000b000810038403850386038703880389038a038b": "FC 16 write 11 x8",
		"00040000000601060064007b":                                   "FC 6 write 100",
		"00070000000f011700280002003200020400070008":                 "FC 23 read 40 x2, write 50 x2",
	}
	l := New()
	for aduHex := range observed {
		l.RecordEvent("10.0.0.1", "10.0.0.2", decodeRequest(t, aduHex))
	}
	generated := l.GenerateRules()
	if len(generated) != 1 {
		t.Fatalf("generated %+v", generated)
	}
	want := []string{"10-11", "100", "11-18", "40-41", "50-51"}
	if got := generated[0].ICS.Addresses; !reflect.DeepEqual(got, want) {
		t.Fatalf("addresses %v, want %v", got, want)
	}
	entry := rules.Entry{ID: "learned", Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: "modbus", Addresses: generated[0].ICS.Addresses}}
	for aduHex, what := range observed {
		if !rules.PreviewMatch(entry, spanContext(decodeRequest(t, aduHex))) {
			t.Errorf("learned rule does not admit the observed %s", what)
		}
	}
	for aduHex, what := range map[string]string{
		"0001000000060103000b0009": "FC 3 read 11 count 9",
		"000100000006010300630002": "FC 3 read 99 count 2",
	} {
		if rules.PreviewMatch(entry, spanContext(decodeRequest(t, aduHex))) {
			t.Errorf("learned rule admits the unobserved %s", what)
		}
	}
}
