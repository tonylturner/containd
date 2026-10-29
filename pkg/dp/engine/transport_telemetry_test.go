// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestTransportAnomalyOmitsAbsentCorrelationReason(t *testing.T) {
	for _, attrs := range []map[string]any{nil, {"correlation_status": nil}, {"correlation_status": "capture_incomplete"}} {
		a := anomaly.Anomaly{Type: "protocol_violation", Protocol: "dnp3", Attributes: attrs}
		ev := anomalyAlertFromEvent(dpi.Event{}, a)
		data, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		wantReason := attrs["correlation_status"] != nil
		if strings.Contains(string(data), `"correlation_status"`) != wantReason {
			t.Fatalf("invented or lost correlation reason: %s", data)
		}
	}
}

func TestTransportInlineAndPCAPReportWireEvidence(t *testing.T) {
	for _, inline := range []bool{false, true} {
		t.Run(map[bool]string{false: "pcap", true: "nfqueue"}[inline], func(t *testing.T) {
			e, err := New(Config{InspectAll: true, DPIEnabled: true})
			if err != nil {
				t.Fatal(err)
			}
			pkt := transportWire(natEvidence().Original, time.Now(), modbusADU(1, 3, 10, 2))
			if inline {
				pkt.Token = capture.NewToken(1, 1)
			}
			e.HandlePacket(pkt)
			evs := transportModbusEvents(e)
			if len(evs) != 1 || evs[0].CorrelationStatus != "wire" || evs[0].TransportConnectionID != "" {
				t.Fatalf("wire-only engine misstated evidence: %+v", evs)
			}
		})
	}
}

func TestTransportOverflowCarriesKnownWireIdentity(t *testing.T) {
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: natEvidence()})
	r.authority.check(context.Background())
	pkt := transportWire(natEvidence().Reply, time.Now(), nil)
	c := r.resolve(context.Background(), pkt, false)
	r.indexed[packetKey(pkt).Tuple()] = c
	r.admissionMu.Lock()
	r.unavailable(e, pkt, "queue_overflow")
	r.admissionMu.Unlock()
	ev := e.Events().List(0)[0]
	key := flow.TupleKey(natEvidence().Reply, flow.DirReverse)
	if ev.Kind != "dpi.correlation.unavailable" || ev.Proto != "modbus" || ev.FlowID != key.Hash() ||
		ev.TransportConnectionID != c.PublicID() || ev.Transport != "tcp" || ev.DstIP != pkt.DstIP.String() {
		t.Fatalf("overflow lacks known wire identity: %+v", ev)
	}
}

func TestTransportStatusImmediatelyReflectsInvalidation(t *testing.T) {
	_, r, _ := newTransportTest(t, &transportCTFake{})
	r.authority.check(context.Background())
	if r.authority.snapshot().ZoneStatus != "verified" {
		t.Fatal("fixture did not verify")
	}
	r.authority.invalidate()
	if r.authority.snapshot().ZoneStatus != "zone_unverified" {
		t.Fatal("status reported verified during invalidation")
	}
}
