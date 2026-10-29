// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestTransportReconfigurePreservesLearnedProfiles(t *testing.T) {
	e, _, _ := newTransportTest(t, &transportCTFake{})
	e.Learner().RecordEvent("10.10.0.5", "10.20.0.4", dpi.Event{Proto: "modbus", Kind: "request",
		Attributes: map[string]any{"function_code": uint8(3), "unit_id": uint8(1), "address": uint16(10), "quantity": uint16(2)}})
	if len(e.Learner().Profiles()) != 1 {
		t.Fatal("fixture did not learn")
	}
	learner := e.Learner()
	fresh, err := New(Config{Events: e.Events()})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Reconfigure(fresh); err != nil {
		t.Fatal(err)
	}
	if e.Learner() != learner || len(e.Learner().Profiles()) != 1 {
		t.Fatal("reconfigure discarded learned profiles")
	}
}

func TestTransportRawSYNDoesNotChangeDenyISNs(t *testing.T) {
	e, _, _ := newTransportTest(t, &transportCTFake{})
	pkt := transportWire(natEvidence().Original, time.Now(), nil)
	pkt.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 100}
	e.HandlePacket(pkt)
	e.flowMu.Lock()
	st := e.tupleStateLocked(natEvidence().Original)
	_, denyRecorded := e.tcpISNs[st.Key.Hash()]
	rawRecorded := e.transportISNs[st.Key.Hash()] == 100
	e.flowMu.Unlock()
	e.HandlePacket(pkt) // retransmission must retain the incarnation
	e.flowMu.Lock()
	same := e.tupleStateLocked(natEvidence().Original) == st
	e.flowMu.Unlock()
	if denyRecorded || !rawRecorded || !same {
		t.Fatal("raw capture SYN changed deny semantics or retired its retransmission")
	}
}

func TestTransportRawSYNExpiryCleansISNs(t *testing.T) {
	e, _, _ := newTransportTest(t, &transportCTFake{})
	pkt := transportWire(natEvidence().Original, time.Now(), nil)
	pkt.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 100}
	e.HandlePacket(pkt)
	if len(e.transportISNs) != 1 {
		t.Fatal("missing transport hint")
	}
	e.sweepFlows(pkt.Timestamp.Add(10 * time.Minute))
	if len(e.transportISNs) != 0 {
		t.Fatal("expired connection leaked transport ISN")
	}
}
