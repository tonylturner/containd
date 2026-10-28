// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package learn

import (
	"encoding/hex"
	"net"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

const learnerSource = "10.0.0.1"
const learnerDest = "10.0.0.2"

func decodeRequest(t *testing.T, aduHex string) dpi.Event {
	t.Helper()
	raw, err := hex.DecodeString(aduHex)
	if err != nil {
		t.Fatal(err)
	}
	state := &flow.State{Key: flow.Key{SrcIP: net.ParseIP(learnerSource), DstIP: net.ParseIP(learnerDest), SrcPort: 40000, DstPort: 502, Proto: 6}}
	evs, err := modbus.NewDecoder().OnPacket(state, &dpi.ParsedPacket{Payload: raw})
	if err != nil || len(evs) != 1 {
		t.Fatalf("decode %s: %d events, %v", aduHex, len(evs), err)
	}
	return evs[0]
}

func modbusContext(t *testing.T, ev dpi.Event, source, dest string) rules.EvalContext {
	t.Helper()
	fc, okFC := eventfields.Uint8(ev.Attributes, eventfields.KeyFunctionCode)
	unit, okUnit := eventfields.Uint8(ev.Attributes, eventfields.KeyUnitID)
	spans, okSpans := modbus.AddressSpans(ev.Attributes)
	ics := &rules.ICSContext{Protocol: "modbus", SpansUnknown: !okSpans}
	if okFC {
		ics.FunctionCode = fc
		ics.HasFunctionCode = true
	}
	if okUnit {
		ics.UnitID = &unit
	}
	if isWrite, ok := eventfields.Bool(ev.Attributes, eventfields.KeyIsWrite); ok {
		ics.ReadOnly = !isWrite
		ics.WriteOnly = isWrite
	}
	for _, span := range spans {
		ics.Spans = append(ics.Spans, rules.AddressSpan{Low: uint32(span.First), High: uint32(span.Last)})
	}
	ics.Direction = ev.Kind
	return rules.EvalContext{SrcIP: net.ParseIP(source), DstIP: net.ParseIP(dest), ICS: ics}
}

func evaluatorForGenerated(generated []config.Rule) *rules.Evaluator {
	entries := make([]rules.Entry, 0, len(generated))
	for _, rule := range generated {
		entries = append(entries, rules.Entry{
			ID:           rule.ID,
			Sources:      rule.Sources,
			Destinations: rule.Destinations,
			Action:       rules.Action(rule.Action),
			ICS: rules.ICSPredicate{
				Protocol:     rule.ICS.Protocol,
				FunctionCode: rule.ICS.FunctionCode,
				UnitID:       rule.ICS.UnitID,
				Addresses:    rule.ICS.Addresses,
				ReadOnly:     rule.ICS.ReadOnly,
				WriteOnly:    rule.ICS.WriteOnly,
				Direction:    rule.ICS.Direction,
			},
		})
	}
	return rules.NewEvaluator(&rules.Snapshot{Default: rules.ActionDeny, Firewall: entries})
}

func TestLearnedModbusRulesCoverOnlyObservedTuples(t *testing.T) {
	observed := map[string]string{
		"0002000000060103000a0002":                                   "FC 3 read 10 count 2",
		"0001000000170110000b000810038403850386038703880389038a038b": "FC 16 write 11 x8",
		"00040000000601060064007b":                                   "FC 6 write 100",
		"00070000000f011700280002003200020400070008":                 "FC 23 read 40 x2, write 50 x2",
	}
	l := New()
	for aduHex := range observed {
		l.RecordEvent(learnerSource, learnerDest, decodeRequest(t, aduHex))
	}
	generated := l.GenerateRules()
	if len(generated) != 4 {
		t.Fatalf("generated %d rules, want one per unit/function tuple: %+v", len(generated), generated)
	}
	wantAddresses := map[string][]string{
		"learned-modbus-10.0.0.1-10.0.0.2-u1-fc03": {"10-11"},
		"learned-modbus-10.0.0.1-10.0.0.2-u1-fc10": {"11-18"},
		"learned-modbus-10.0.0.1-10.0.0.2-u1-fc06": {"100"},
		"learned-modbus-10.0.0.1-10.0.0.2-u1-fc17": {"40-41", "50-51"},
	}
	for _, generatedRule := range generated {
		want, ok := wantAddresses[generatedRule.ID]
		if !ok {
			t.Errorf("unexpected generated rule ID %q", generatedRule.ID)
			continue
		}
		if !reflect.DeepEqual(generatedRule.ICS.Addresses, want) {
			t.Errorf("%s addresses %v, want %v", generatedRule.ID, generatedRule.ICS.Addresses, want)
		}
		delete(wantAddresses, generatedRule.ID)
	}
	if len(wantAddresses) != 0 {
		t.Errorf("missing generated rules for %v", wantAddresses)
	}

	evaluator := evaluatorForGenerated(generated)
	for aduHex, what := range observed {
		if got := evaluator.Evaluate(modbusContext(t, decodeRequest(t, aduHex), learnerSource, learnerDest)); got != rules.ActionAllow {
			t.Errorf("generated rules do not admit observed %s: %s", what, got)
		}
	}
	for _, tc := range []struct {
		name      string
		unit      uint8
		fc        uint8
		direction string
		readOnly  bool
		writeOnly bool
		span      rules.AddressSpan
	}{
		{name: "unseen unit at unit 1 address", unit: 3, fc: 3, direction: "request", readOnly: true, span: rules.AddressSpan{Low: 10, High: 11}},
		{name: "unit 1 at unit 2 address", unit: 1, fc: 3, direction: "request", readOnly: true, span: rules.AddressSpan{Low: 20, High: 21}},
		{name: "FC 16 at FC 3 address", unit: 1, fc: 16, direction: "request", writeOnly: true, span: rules.AddressSpan{Low: 10, High: 11}},
		{name: "FC 3 at FC 16 address", unit: 1, fc: 3, direction: "request", readOnly: true, span: rules.AddressSpan{Low: 11, High: 18}},
		{name: "response direction", unit: 1, fc: 16, direction: "response", writeOnly: true, span: rules.AddressSpan{Low: 11, High: 18}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := rules.EvalContext{
				SrcIP: net.ParseIP(learnerSource),
				DstIP: net.ParseIP(learnerDest),
				ICS: &rules.ICSContext{
					Protocol:        "modbus",
					HasFunctionCode: true,
					FunctionCode:    tc.fc,
					UnitID:          &tc.unit,
					Direction:       tc.direction,
					ReadOnly:        tc.readOnly,
					WriteOnly:       tc.writeOnly,
					Spans:           []rules.AddressSpan{tc.span},
				},
			}
			if got := evaluator.Evaluate(ctx); got != rules.ActionDeny {
				t.Errorf("generated rules admit unobserved tuple: %s", got)
			}
		})
	}

	if again := l.GenerateRules(); !reflect.DeepEqual(generated, again) {
		t.Fatalf("rule generation is not deterministic:\nfirst:  %+v\nsecond: %+v", generated, again)
	}
}

func TestLearnedRuleEvaluatorRejectsF02CrossProducts(t *testing.T) {
	l := New()
	request := func(unit, fc uint8, address, quantity uint16, isWrite bool) dpi.Event {
		attrs := map[string]any{
			"unit_id":       unit,
			"function_code": fc,
			"address":       address,
			"quantity":      quantity,
			"is_write":      isWrite,
		}
		if fc == 16 {
			attrs["byte_count"] = uint8(2 * quantity)
		}
		return dpi.Event{Proto: eventfields.ProtoModbus, Kind: eventfields.KindRequest, Attributes: attrs}
	}

	observed := []dpi.Event{
		request(1, 3, 10, 2, false),
		request(2, 3, 20, 2, false),
		request(1, 16, 20, 2, true),
	}
	for _, event := range observed {
		l.RecordEvent(learnerSource, learnerDest, event)
	}
	generated := l.GenerateRules()
	if len(generated) != 3 {
		t.Fatalf("generated %d rules, want three exact tuples: %+v", len(generated), generated)
	}
	evaluator := evaluatorForGenerated(generated)
	for _, event := range observed {
		if got := evaluator.Evaluate(modbusContext(t, event, learnerSource, learnerDest)); got != rules.ActionAllow {
			t.Errorf("generated rule rejected observed unit/function tuple: %s", got)
		}
	}

	unobserved := []struct {
		name  string
		event dpi.Event
	}{
		{"unit 3 at unit 1 address", request(3, 3, 10, 2, false)},
		{"unit 1 at unit 2 address", request(1, 3, 20, 2, false)},
		{"unit 1 FC 16 at unit 1 FC 3 address", request(1, 16, 10, 2, true)},
		{"unit 1 FC 3 at unit 1 FC 16 address", request(1, 3, 20, 2, false)},
	}
	for _, tc := range unobserved {
		t.Run(tc.name, func(t *testing.T) {
			if got := evaluator.Evaluate(modbusContext(t, tc.event, learnerSource, learnerDest)); got != rules.ActionDeny {
				t.Errorf("generated rule admits unobserved tuple: %s", got)
			}
		})
	}
}

func TestModbusUnknownSpansProduceNoLearnedRule(t *testing.T) {
	l := New()
	l.RecordEvent(learnerSource, learnerDest, dpi.Event{
		Proto: eventfields.ProtoModbus, Kind: eventfields.KindRequest,
		Attributes: map[string]any{"function_code": uint8(0x41), "unit_id": uint8(1)},
	})
	if profiles := l.Profiles(); len(profiles) != 0 {
		t.Fatalf("unsupported request created a profile: %+v", profiles)
	}
	if generated := l.GenerateRules(); len(generated) != 0 {
		t.Fatalf("unknown spans generated an addressless rule: %+v", generated)
	}
}
