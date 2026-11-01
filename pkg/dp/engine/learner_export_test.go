// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

// NewLearnerOverflowEngine exposes controlled transport admission only to the
// external integration test. No production test switches or kernel I/O exist.
// NAT variants retain one wire face only and lose the other face.
func NewLearnerOverflowEngine(t *testing.T, variant string) (*Engine, func(bool), func(), func(), func(bool)) {
	t.Helper()
	ct := natEvidence()
	if strings.HasPrefix(variant, "DNAT") {
		ct.Original.Destination = netip.MustParseAddrPort("10.10.0.1:502")
		ct.Reply.Destination = ct.Original.Source
	}
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: ct})
	r.authority.check(context.Background())
	drain := func() {
		select {
		case notice := <-r.losses:
			e.consumeDecodeLoss(notice, r.resolve(context.Background(), notice.packet, false))
		default:
			t.Fatal("real transport byte overflow failed to notify")
		}
	}
	lost := ct.Original
	if variant == "SNAT" {
		lost = ct.Reply
	}
	truncate := func(ports bool) {
		pkt := transportWire(lost, time.Now(), nil)
		pkt.Invalid, pkt.CaptureIncomplete, pkt.PortsValid = capture.InvalidTCPHeader, true, ports
		if !ports {
			pkt.SrcPort, pkt.DstPort = 0, 0
		}
		e.HandlePacket(pkt)
	}
	var next capture.Packet
	emit := func() { r.admit(e, next); processTransportAdmission(t, e, r) }
	return e, func(loss bool) {
		at := time.Now()
		pkt := transportWire(ct.Original, at, nil)
		pkt.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 100}
		r.admit(e, pkt)
		processTransportAdmission(t, e, r)
		payload := modbusADU(1, 3, 10, 2)
		if variant == "DNAT response" {
			pkt = transportWire(ct.Reply, at.Add(time.Microsecond), nil)
			pkt.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN | capture.TCPFlagACK, Seq: 200}
			r.admit(e, pkt)
			processTransportAdmission(t, e, r)
			// FC6 echoes a complete address/value parent. Response directions are
			// deliberately not command suggestions; the regression checks loss
			// authority independently of this unsupported-operation withholding.
			payload = modbusADU(1, 6, 10, 2)
		}
		pkt.Timestamp, pkt.Payload = at.Add(time.Millisecond), payload
		pkt.TCP.Flags = capture.TCPFlagACK
		pkt.TCP.Seq++
		r.admit(e, pkt)
		processTransportAdmission(t, e, r)
		events := transportModbusEvents(e)
		if len(events) != 1 || variant == "DNAT response" && events[0].Kind != "response" {
			t.Fatalf("missing directional parent: %+v", events)
		}
		next = pkt
		next.Timestamp = at.Add(1500 * time.Microsecond)
		next.TCP.Seq += uint32(len(payload))
		next.Payload = modbusADU(2, 3, 10, 2)
		if variant == "DNAT response" {
			next.Payload = modbusADU(2, 6, 10, 2)
		}
		if loss {
			pkt = transportWire(lost, at.Add(2*time.Millisecond), make([]byte, transportByteLimit+1))
			pkt.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagACK, Seq: 1}
			r.admit(e, pkt)
		}
	}, drain, emit, truncate
}
