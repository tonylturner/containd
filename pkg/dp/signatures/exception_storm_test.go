// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package signatures

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
)

// modbusResponse decodes a real Modbus/TCP response from the server
// (port 502) with function code fc and a 2-byte body.
func modbusResponse(t *testing.T, sport uint16, fc byte, body ...byte) dpi.Event {
	t.Helper()
	pdu := append([]byte{fc}, body...)
	adu := append([]byte{0x00, 0x01, 0x00, 0x00, 0x00, byte(1 + len(pdu)), 0x01}, pdu...)
	key := flow.Key{SrcIP: net.ParseIP("10.0.0.2"), DstIP: net.ParseIP("10.0.0.1"), SrcPort: 502, DstPort: sport, Proto: 6}
	evs, err := modbus.NewDecoder().OnPacket(flow.NewState(key, time.Now()), &dpi.ParsedPacket{Payload: adu, Proto: "tcp", SrcPort: 502, DstPort: sport})
	if err != nil || len(evs) != 1 {
		t.Fatalf("decode FC %#x: events=%d err=%v", fc, len(evs), err)
	}
	return evs[0]
}

func stormAlerts(e *Engine, evs []dpi.Event) int {
	n := 0
	for _, ev := range evs {
		for _, m := range e.Match(ev) {
			if m.Signature.ID == "MODBUS-EXCEPTION-STORM" {
				n++
			}
		}
	}
	return n
}

func burst(ev dpi.Event, n int, start time.Time) []dpi.Event {
	out := make([]dpi.Event, n)
	for i := range out {
		out[i] = ev
		out[i].Timestamp = start.Add(time.Duration(i) * time.Second)
	}
	return out
}

func TestModbusExceptionStormFiresOncePerWindow(t *testing.T) {
	// Illegal data address (code 2) for a read holding registers request.
	exc := modbusResponse(t, 40000, 0x83, 0x02)
	if exc.Kind != "exception" {
		t.Fatalf("decoded kind = %q, want exception", exc.Kind)
	}
	raw, err := json.Marshal(exc.Attributes)
	if err != nil {
		t.Fatal(err)
	}
	excJSON := exc
	if err := json.Unmarshal(raw, &excJSON.Attributes); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	for _, ev := range []dpi.Event{exc, excJSON} {
		e := New()
		e.LoadBuiltins()
		if got := stormAlerts(e, burst(ev, modbusExceptionStormCount-1, t0)); got != 0 {
			t.Fatalf("%d exceptions fired %d alerts, want 0", modbusExceptionStormCount-1, got)
		}
		if got := stormAlerts(e, burst(ev, 1, t0.Add(20*time.Second))); got != 1 {
			t.Fatalf("the %dth exception in the window fired %d alerts, want 1", modbusExceptionStormCount, got)
		}
		if got := stormAlerts(e, burst(ev, 20, t0.Add(21*time.Second))); got != 0 {
			t.Fatalf("more exceptions in the same window fired %d alerts, want 0", got)
		}
		// A new window can fire again.
		if got := stormAlerts(e, burst(ev, modbusExceptionStormCount, t0.Add(2*modbusExceptionStormWindowSeconds*time.Second))); got != 1 {
			t.Fatalf("next window fired %d alerts, want 1", got)
		}
	}
}

func TestModbusExceptionStormIgnoresNormalResponsesAndOtherFlows(t *testing.T) {
	e := New()
	e.LoadBuiltins()
	t0 := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	// Normal read responses (FC 3, byte count 2, one register).
	normal := modbusResponse(t, 40000, 0x03, 0x02, 0x00, 0x01)
	if got := stormAlerts(e, burst(normal, 50, t0)); got != 0 {
		t.Fatalf("normal responses fired %d storm alerts", got)
	}
	// Exceptions spread over two flows stay below the threshold on each.
	a := burst(modbusResponse(t, 40000, 0x83, 0x02), modbusExceptionStormCount/2, t0)
	b := burst(modbusResponse(t, 40001, 0x86, 0x03), modbusExceptionStormCount/2, t0)
	if got := stormAlerts(e, append(a, b...)); got != 0 {
		t.Fatalf("exceptions split across flows fired %d alerts", got)
	}
	// Exceptions slower than the window never accumulate.
	slow := modbusResponse(t, 40002, 0x83, 0x02)
	var spread []dpi.Event
	for i := 0; i < 3*modbusExceptionStormCount; i++ {
		ev := slow
		ev.Timestamp = t0.Add(time.Duration(i) * (modbusExceptionStormWindowSeconds * time.Second / 5))
		spread = append(spread, ev)
	}
	if got := stormAlerts(e, spread); got != 0 {
		t.Fatalf("exceptions slower than the window fired %d alerts", got)
	}
}

func TestThresholdCountersAreBounded(t *testing.T) {
	e := New()
	e.Add(Signature{ID: "T", Protocol: "x", Conditions: []Condition{{Field: "kind", Op: "equals", Value: "k"}},
		Threshold: &Threshold{Count: 2, WindowSeconds: 3600}})
	t0 := time.Now()
	for i := 0; i < maxThresholdKeys+10; i++ {
		e.Match(dpi.Event{Proto: "x", Kind: "k", FlowID: string(rune(i)), Timestamp: t0})
	}
	if len(e.thresholds) > maxThresholdKeys {
		t.Fatalf("threshold counters = %d, bound %d", len(e.thresholds), maxThresholdKeys)
	}
}
