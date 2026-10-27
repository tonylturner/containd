// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package signatures

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func writeStormEvent(flowID, proto, kind string, write bool, timestamp time.Time, apduID string) dpi.Event {
	attrs := map[string]any{"is_write": write}
	if apduID != "" {
		attrs["apdu_id"] = apduID
	}
	return dpi.Event{
		FlowID:     flowID,
		Proto:      proto,
		Kind:       kind,
		Attributes: attrs,
		Timestamp:  timestamp,
	}
}

func writeStormAlert(e *Engine, ev dpi.Event) bool {
	for _, m := range e.Match(ev) {
		if m.Signature.ID == "ICS-WRITE-STORM" {
			return true
		}
	}
	return false
}

func TestICSWriteStormCountsInitiatorCommandsOncePerConnection(t *testing.T) {
	e := New()
	e.LoadBuiltins()
	start := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	forward := flow.Key{
		SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"),
		SrcPort: 40000, DstPort: 2404, Proto: 6, Dir: flow.DirForward,
	}
	for i := 0; i < 19; i++ {
		ev := writeStormEvent(forward.Hash(), "iec104", "request", true,
			start.Add(time.Duration(i)*500*time.Millisecond), "session/c/"+strconv.Itoa(i))
		if writeStormAlert(e, ev) {
			t.Fatalf("alerted after %d write commands, want 20", i+1)
		}
	}
	last := writeStormEvent(forward.Reversed().Hash(), "iec104", "request", true,
		start.Add(9500*time.Millisecond), "session/s/1")
	if !writeStormAlert(e, last) {
		t.Fatal("20th command on the reverse flow hash did not alert for the same connection")
	}
	if writeStormAlert(e, last) {
		t.Fatal("write-storm signature alerted more than once in the window")
	}

	// Distinct connections must not share their count.
	other := New()
	other.LoadBuiltins()
	different := flow.Key{
		SrcIP: net.ParseIP("10.0.0.3"), DstIP: net.ParseIP("10.0.0.4"),
		SrcPort: 40000, DstPort: 2404, Proto: 6, Dir: flow.DirForward,
	}
	for i := 0; i < 10; i++ {
		ev := writeStormEvent(different.Hash(), "iec104", "request", true,
			start.Add(time.Duration(i)*time.Second), "other/c/"+strconv.Itoa(i))
		if writeStormAlert(other, ev) {
			t.Fatalf("separate connection alerted after only %d commands", i+1)
		}
	}
}

func TestICSWriteStormFiltersRepliesAndExceptions(t *testing.T) {
	e := New()
	e.LoadBuiltins()
	start := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	flowID := "10.0.0.1|10.0.0.2|40000|502|006|0"
	if writeStormAlert(e, writeStormEvent(flowID, "modbus", "request", true, start, "")) {
		t.Fatal("one write command alerted")
	}
	for _, kind := range []string{"response", "exception", "malformed", "unsupported"} {
		for i := 0; i < 30; i++ {
			ev := writeStormEvent(flowID, "modbus", kind, true, start.Add(time.Duration(i)*time.Millisecond), "")
			if writeStormAlert(e, ev) {
				t.Fatalf("%s event counted as an initiator command", kind)
			}
		}
	}
	for i := 1; i < 20; i++ {
		ev := writeStormEvent(flowID, "modbus", "request", true, start.Add(time.Duration(i)*500*time.Millisecond), "")
		if got := writeStormAlert(e, ev); got != (i == 19) {
			t.Fatalf("request %d alert = %v, want %v", i+1, got, i == 19)
		}
	}
}

func TestICSWriteStormCountsDNP3CommandKinds(t *testing.T) {
	for _, kind := range []string{"restart", "control"} {
		t.Run(kind, func(t *testing.T) {
			e := New()
			e.LoadBuiltins()
			start := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
			flowID := "10.0.0.1|10.0.0.2|40000|20000|006|0"
			for i := 0; i < 20; i++ {
				ev := writeStormEvent(flowID, "dnp3", kind, true,
					start.Add(time.Duration(i)*500*time.Millisecond), "")
				if got := writeStormAlert(e, ev); got != (i == 19) {
					t.Fatalf("command %d alert = %v, want %v", i+1, got, i == 19)
				}
			}
		})
	}
}

func TestICSWriteStormCountsIEC104APDUOnce(t *testing.T) {
	e := New()
	e.LoadBuiltins()
	start := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	flowID := "10.0.0.1|10.0.0.2|40000|2404|006|0"

	for apdu := 0; apdu < 19; apdu++ {
		id := "session/c/" + strconv.Itoa(apdu)
		for object := 0; object < 3; object++ {
			ev := writeStormEvent(flowID, "iec104", "request", true,
				start.Add(time.Duration(apdu)*500*time.Millisecond), id)
			if writeStormAlert(e, ev) {
				t.Fatalf("alerted during APDU %d object %d; expected 20 APDUs", apdu+1, object+1)
			}
		}
	}
	lastID := "session/c/19"
	lastAt := start.Add(9500 * time.Millisecond)
	for object := 0; object < 3; object++ {
		ev := writeStormEvent(flowID, "iec104", "request", true, lastAt, lastID)
		if got := writeStormAlert(e, ev); got != (object == 0) {
			t.Fatalf("20th APDU object %d alert = %v, want %v", object+1, got, object == 0)
		}
	}

	// A repeated command with a distinct APDU identity is a new occurrence,
	// while events with the same APDU identity remain one occurrence.
	e = New()
	e.LoadBuiltins()
	for _, id := range []string{"same-bytes/1", "same-bytes/1", "same-bytes/2"} {
		if writeStormAlert(e, writeStormEvent(flowID, "iec104", "request", true, start, id)) {
			t.Fatalf("three APDUs alerted before the 20-command threshold")
		}
	}
	st := e.thresholds[thresholdKey{sigID: "ICS-WRITE-STORM", flowID: connectionFlowID(flowID)}]
	if st == nil || st.count != 2 {
		t.Fatalf("distinct APDU command count = %v, want 2", st)
	}
}

func TestICSWriteStormWindowBoundary(t *testing.T) {
	e := New()
	e.LoadBuiltins()
	start := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	flowID := "10.0.0.1|10.0.0.2|40000|502|006|0"
	for i := 0; i < 19; i++ {
		if writeStormAlert(e, writeStormEvent(flowID, "modbus", "request", true, start, "")) {
			t.Fatalf("alerted after %d commands", i+1)
		}
	}
	atBoundary := writeStormEvent(flowID, "modbus", "request", true,
		start.Add(10*time.Second), "")
	if !writeStormAlert(e, atBoundary) {
		t.Fatal("an event exactly at the configured window boundary did not complete the window")
	}

	afterBoundary := start.Add(10*time.Second + time.Nanosecond)
	for i := 0; i < 19; i++ {
		ev := writeStormEvent(flowID, "modbus", "request", true, afterBoundary, "")
		if writeStormAlert(e, ev) {
			t.Fatalf("expired window reused prior count at command %d", i+1)
		}
	}
	if !writeStormAlert(e, writeStormEvent(flowID, "modbus", "request", true, afterBoundary, "")) {
		t.Fatal("20 commands in the restarted window did not alert")
	}
}

func TestConnectionFlowIDCanonicalizesBothDirections(t *testing.T) {
	forward := flow.Key{
		SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"),
		SrcPort: 40000, DstPort: 502, Proto: 6, Dir: flow.DirForward,
	}
	reverse := forward.Reversed()
	if got, want := connectionFlowID(forward.Hash()), connectionFlowID(reverse.Hash()); got != want {
		t.Fatalf("forward connection ID %q differs from reverse %q", got, want)
	}
}
