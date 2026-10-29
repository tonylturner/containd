// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/identify"
	"github.com/tonylturner/containd/pkg/dp/observe"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestLegacyDecodesAndScope(t *testing.T) {
	for _, tc := range []struct {
		name            string
		port, source    uint16
		selected, owned bool
		p               identify.Protocol
		want            bool
	}{
		{"match", 502, 41000, true, false, identify.Modbus, true},
		{"unselected", 502, 41000, false, false, identify.Modbus, false},
		{"mismatch", 20000, 41000, true, false, identify.Modbus, false},
		{"source-registry", 41000, 502, true, false, identify.Modbus, true},
		{"IEC-bypass", 502, 2404, true, false, identify.Modbus, false},
		{"IEC-unowned", 2404, 41000, true, false, identify.IEC104, false},
		{"IEC-table", 2404, 41000, false, true, identify.IEC104, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := packetKey(observationTrace(tc.port, false)[0])
			key.SrcPort = tc.source
			state := flow.NewState(key, time.Now())
			ctx := &observationContext{states: [2]*flow.State{state, nil}, selected: tc.selected, iecOwned: tc.owned}
			if got := legacyDecodes(ctx, tc.p); got != tc.want {
				t.Fatalf("legacy=%v want %v", got, tc.want)
			}
		})
	}
	state := flow.NewState(packetKey(observationTrace(1502, false)[0]), time.Now())
	ctx := &observationContext{states: [2]*flow.State{state, nil}}
	if observationScope(ctx, identify.Modbus) != "unknown" {
		t.Fatal("no snapshot must be unknown")
	}
	ctx.snapshot = &rules.Snapshot{Firewall: []rules.Entry{{ICS: rules.ICSPredicate{Protocol: "modbus"}}}}
	if observationScope(ctx, identify.Modbus) != true {
		t.Fatal("implicit registry port must not cover alternate port")
	}
	ctx.snapshot.Firewall[0].Protocols = []rules.Protocol{{Name: "tcp", Port: "1500-1510"}}
	ctx.snapshot.Firewall[0].Sources = []string{"192.0.2.1/32"}
	if observationScope(ctx, identify.Modbus) != false {
		t.Fatal("scope must use port/transport, not address predicates")
	}
	ctx.snapshot.Firewall[0].Protocols[0].Name = "udp"
	if observationScope(ctx, identify.Modbus) != true {
		t.Fatal("transport conjunction missing")
	}
	if observationScope(ctx, identify.DNP3) != false {
		t.Fatal("absent protocol has no outside-scope finding")
	}
	ctx.snapshot.Firewall = append(ctx.snapshot.Firewall, rules.Entry{})
	if observationScope(ctx, "") != false {
		t.Fatal("ordinary L4 rules cannot name an unidentified protocol")
	}
}

func TestObservationExclusionsAndConsumers(t *testing.T) {
	for _, port := range []uint16{1502, 2404} {
		t.Run(map[uint16]string{1502: "alternate", 2404: "IEC-domain"}[port], func(t *testing.T) {
			e := newObservationEngine(t)
			e.dpiExclusions = []DPIExclusion{{Type: "domain", Value: "excluded.example"}}
			e.domains = newDomainExclusions(e.dpiExclusions)
			trace := observationTrace(port, false)
			ip, _ := netip.AddrFromSlice(trace[0].DstIP)
			e.domains.add(ip, "excluded.example", 300)
			for _, p := range trace {
				e.HandlePacket(p)
			}
			got := e.observation.observer.Counters()
			if got.Bindings != 0 || got.Evidence.Confirms != 0 {
				t.Fatalf("excluded content probed/bound: %+v", got)
			}
		})
	}
	e := newObservationEngine(t)
	for _, p := range observationTrace(1502, false) {
		e.HandlePacket(p)
	}
	if len(e.Learner().Profiles()) != 0 || len(e.Learner().GenerateRules()) != 0 {
		t.Fatal("passive connection entered portless learner")
	}
	trace := observationTrace(1502, false)
	state := e.tupleStateLocked(packetKey(trace[0]).Tuple())
	e.sweepFlows(trace[0].Timestamp.Add(6 * time.Minute))
	e.RecordDPIEvents(state, observationPacket(state), []dpi.Event{{Proto: "modbus", Kind: "request", Attributes: map[string]any{"observation_only": true, "function_code": uint8(3), "unit_id": uint8(1)}}})
	if len(e.Learner().Profiles()) != 0 {
		t.Fatal("retired passive event entered learner without a live marker")
	}
	if len(e.Inventory().List()) == 0 {
		t.Fatal("passive telemetry inventory suppressed")
	}
	for _, p := range e.ProtoStats() {
		if p.Protocol == "identify" {
			t.Fatal("identification entered semantic operation counters")
		}
	}
}

func TestObservationSettledAdmissionAndMetrics(t *testing.T) {
	e := newObservationEngine(t)
	trace := observationTrace(1502, false)
	before := testutil.ToFloat64(metrics.IdentificationOutcomes.WithLabelValues("modbus", "confirmed"))
	for _, p := range trace {
		e.handleTransportPacket(p, &flow.Connection{Key: "test-ct", Status: "not_found"}, nil)
	}
	continuation := trace[2]
	if e.transportEligible(continuation) {
		t.Fatal("settled tuple reentered resolver")
	}
	continuation.TCP = trace[0].TCP
	continuation.TCP.Seq++
	if !e.transportEligible(continuation) {
		t.Fatal("fresh ISN failed admission")
	}
	e.observation.syncMetrics()
	if delta := testutil.ToFloat64(metrics.IdentificationOutcomes.WithLabelValues("modbus", "confirmed")) - before; delta != 1 {
		t.Fatalf("snapshot counter diff=%v", delta)
	}
	e.observation.syncMetrics()
	if delta := testutil.ToFloat64(metrics.IdentificationOutcomes.WithLabelValues("modbus", "confirmed")) - before; delta != 1 {
		t.Fatalf("snapshot recounted=%v", delta)
	}
	// Packet arguments remain passive: no inline token is fabricated.
	if continuation.Token.Inline() || continuation.Proto != 6 || continuation.TCP.Flags&capture.TCPFlagSYN == 0 {
		t.Fatal("invalid admission fixture")
	}
}

func TestObservationRefusalAndDirectionExpiry(t *testing.T) {
	e := newObservationEngine(t)
	manager, err := dpi.NewObservationManager(modbus.NewDecoder())
	if err != nil {
		t.Fatal(err)
	}
	budgets := identify.DefaultBudgets()
	budgets.Protocols = []identify.Protocol{identify.Modbus}
	e.observation.observer, err = observe.New(observe.Options{Budgets: budgets, Markers: 1, Now: time.Now, Manager: manager})
	if err != nil {
		t.Fatal(err)
	}
	trace := observationTrace(1502, false)
	for _, p := range trace {
		e.HandlePacket(p)
	}
	key := identify.Key(e.tupleStateLocked(packetKey(trace[0]).Tuple()).Connection.Load().Key)
	other := trace[0]
	other.SrcPort++
	for range 5 {
		e.HandlePacket(other)
	}
	if got := e.observation.observer.Counters().Refusals; got != 1 {
		t.Fatalf("refused incarnation retried: %d", got)
	}
	// Expire only the request direction. Its peer must retain the Observed
	// marker for learner exclusion, but no live decoder stream.
	now := trace[0].Timestamp.Add(6 * time.Minute)
	peer := e.tupleStateLocked(packetKey(trace[1]).Tuple())
	peer.LastSeen = now
	e.sweepFlows(now)
	status, ok := e.observation.observer.Lookup(key)
	if !ok || !status.Observed || status.Binding != observe.None || !e.observationBound(peer) {
		t.Fatalf("direction expiry lost passive marker: %+v", status)
	}
	e.sweepFlows(now.Add(6 * time.Minute))
	if got := e.observation.observer.Counters().Markers; got != 0 {
		t.Fatalf("expired markers=%d", got)
	}
}

func TestObservationFindingsAlwaysPassed(t *testing.T) {
	e := newObservationEngine(t)
	e.SetICSParsing(map[string]string{"modbus": "strict"})
	e.LoadRules(rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{{ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "enforce"}, Action: rules.ActionDeny}}})
	trace := observationTrace(1502, false)
	for _, p := range trace {
		e.HandlePacket(p)
	}
	next := trace[2]
	next.TCP.Seq += uint32(len(next.Payload))
	next.Payload = modbusADU(2, 3, 0, 2)
	next.Payload[3] = 1
	if d := e.HandlePacket(next); d.Action != capture.Accept {
		t.Fatalf("passive finding changed verdict: %+v", d)
	}
	alerts := 0
	for _, event := range e.Events().List(0) {
		if event.Kind == "ics.decision" {
			t.Fatalf("passive finding evaluated policy: %+v", event)
		}
		if event.Proto == "ids" && event.Kind == "alert" {
			alerts++
			if event.Attributes["action"] != "passed" {
				t.Fatalf("finding action: %+v", event)
			}
		}
	}
	if alerts != 1 {
		t.Fatalf("passed conformance alerts=%d", alerts)
	}
}
