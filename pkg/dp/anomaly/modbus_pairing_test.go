// SPDX-License-Identifier: Apache-2.0

package anomaly

import (
	"fmt"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func pairingEvent(port uint16, tid uint16, unit uint8, reply bool, incarnation string) dpi.Event {
	key := modbusFlowID("10.0.0.1", "10.0.0.2", port, 502, flow.DirForward)
	kind := "request"
	if reply {
		key = modbusFlowID("10.0.0.2", "10.0.0.1", 502, port, flow.DirReverse)
		kind = "response"
	}
	c := &flow.Connection{Key: incarnation, Status: "offline"}
	c.Coverage().Store(true)
	return dpi.Event{FlowID: key, Connection: c, Proto: "modbus", Kind: kind, Timestamp: time.Now(),
		Attributes: map[string]any{"transaction_id": tid, "unit_id": unit, "function_code": uint8(3)}}
}

func TestModbusPairingScopesPortUnitDirectionAndIncarnation(t *testing.T) {
	d := New()
	request := pairingEvent(41000, 7, 1, false, "a")
	if got := d.Check("10.0.0.1", "10.0.0.2", request); len(got) != 0 {
		t.Fatal(got)
	}
	for _, wrong := range []dpi.Event{
		pairingEvent(41001, 7, 1, true, "b"),
		pairingEvent(41000, 7, 2, true, "a"),
		pairingEvent(41000, 7, 1, true, "new-incarnation"),
	} {
		got := d.Check("10.0.0.2", "10.0.0.1", wrong)
		if len(got) != 1 || got[0].Type != "protocol_violation" || d.PairingStats().PendingTransactions != 1 {
			t.Fatalf("cross-consumed request: %+v, %+v", got, d.PairingStats())
		}
	}
	// A request sent in the reverse direction is a different pending key.
	reverseRequest := pairingEvent(41000, 7, 1, true, "a")
	reverseRequest.Kind = "request"
	d.Check("10.0.0.2", "10.0.0.1", reverseRequest)
	if d.PairingStats().PendingTransactions != 2 {
		t.Fatal("request directions collapsed")
	}
	if got := d.Check("10.0.0.2", "10.0.0.1", pairingEvent(41000, 7, 1, true, "a")); len(got) != 0 {
		t.Fatal(got)
	}
	if d.PairingStats().PendingTransactions != 1 || d.PairingStats().Matched != 1 {
		t.Fatal("wrong directional request consumed")
	}
	d.ForgetConnection("a")
	if d.PairingStats().PendingTransactions != 0 {
		t.Fatal("close retained pending requests")
	}
}

func TestModbusUnresolvedDoesNotClaimUnmatchedReply(t *testing.T) {
	for _, status := range []string{"zone_unverified", "not_found", "lookup_error", "unsupported_zone", "identity_frozen"} {
		d := New()
		ev := pairingEvent(41000, 7, 1, true, "unresolved")
		ev.Connection = &flow.Connection{Key: "unresolved", Status: status}
		got := d.Check("10.0.0.2", "10.0.0.1", ev)
		if len(got) != 1 || got[0].Type != "correlation_unavailable" || got[0].Attributes["correlation_status"] != status {
			t.Fatalf("%s: %+v", status, got)
		}
	}
}

func TestModbusPendingBoundsAndExpiry(t *testing.T) {
	d := New(WithTotalRateThreshold(100000))
	for i := 0; i < maxPendingPerConnection+1; i++ {
		d.Check("10.0.0.1", "10.0.0.2", pairingEvent(41000, uint16(i), 1, false, "bounded"))
	}
	if s := d.PairingStats(); s.PendingTransactions != maxPendingPerConnection || s.Capacity != 1 {
		t.Fatalf("pending transaction cap: %+v", s)
	}
	reply := pairingEvent(41000, 65000, 1, true, "bounded")
	if got := d.Check("10.0.0.2", "10.0.0.1", reply); len(got) != 1 || got[0].Type != "correlation_unavailable" {
		t.Fatalf("overflow claimed unmatched: %+v", got)
	}
	d.Clear()
	for i := 0; i < maxPendingConnections+1; i++ {
		d.Check("10.0.0.1", "10.0.0.2", pairingEvent(41000, 1, 1, false, fmt.Sprint(i)))
	}
	if s := d.PairingStats(); s.PendingConnections != maxPendingConnections || s.Capacity != 1 {
		t.Fatalf("pending connection cap: %+v", s)
	}
	d.Clear()
	req := pairingEvent(41000, 1, 1, false, "expires")
	d.Check("10.0.0.1", "10.0.0.2", req)
	reply = pairingEvent(41000, 1, 1, true, "expires")
	reply.Timestamp = req.Timestamp.Add(pendingTTL + time.Second)
	got := d.Check("10.0.0.2", "10.0.0.1", reply)
	if len(got) != 1 || got[0].Type != "correlation_unavailable" || d.PairingStats().Expired != 1 {
		t.Fatalf("expired pending request: %+v, %+v", got, d.PairingStats())
	}
}

func TestModbusExpiredBucketRetainsCoverageLossAcrossSnapshots(t *testing.T) {
	d := New()
	req := pairingEvent(41000, 1, 1, false, "expires")
	d.Check("10.0.0.1", "10.0.0.2", req)
	reply := pairingEvent(41000, 1, 1, true, "expires")
	reply.Connection.InheritLifecycle(req.Connection)
	reply.Timestamp = req.Timestamp.Add(2*pendingTTL + time.Second)
	got := d.Check("10.0.0.2", "10.0.0.1", reply)
	if len(got) != 1 || got[0].Type != "correlation_unavailable" || d.PairingStats().PendingConnections != 0 {
		t.Fatalf("idle retirement claimed a known unmatched reply: %+v", got)
	}
}
