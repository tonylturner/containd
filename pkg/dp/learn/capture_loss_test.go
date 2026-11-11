// SPDX-License-Identifier: Apache-2.0
package learn

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/evidence"
)

func ipv6LossPacket(nextHeader uint8, payload []byte, missing int) capture.Packet {
	raw := make([]byte, 40+len(payload))
	raw[0] = 0x60
	binary.BigEndian.PutUint16(raw[4:6], uint16(len(payload)+missing))
	raw[6] = nextHeader
	copy(raw[8:24], net.ParseIP("2001:db8::1").To16())
	copy(raw[24:40], net.ParseIP("2001:db8::2").To16())
	copy(raw[40:], payload)
	return capture.DecodeIPPacket(raw)
}

func TestIPv4NonTransportTruncationDoesNotExclude(t *testing.T) {
	for _, proto := range []byte{0, 1, 2, 43, 44, 51, 60, 135, 139, 140, 253, 254} {
		pkt := capture.Packet{IPVersion: 4, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), Proto: proto, CaptureIncomplete: true}
		loss := CaptureLoss(pkt, "capture_loss")
		if loss.Code != "capture_unrelated" {
			t.Fatalf("protocol %d excluded: %+v", proto, loss)
		}
	}
}

func TestIPv6OpaqueTruncationStillExcludes(t *testing.T) {
	for _, proto := range []byte{0, 43, 44, 51, 60, 58} {
		raw := make([]byte, 48)
		raw[0], raw[5], raw[6] = 0x60, 64, proto
		raw[23], raw[39] = 1, 2
		pkt := capture.DecodeIPPacket(raw)
		if !pkt.CaptureIncomplete {
			t.Fatal("fixture did not retain IP truncation", pkt)
		}
		loss := CaptureLoss(pkt, "capture_loss")
		ds := evidence.Dataset{}
		ds.RecordLoss(loss)
		if got := ds.LossTouches(evidence.Observation{ConnectionID: "connection"}); got != (proto != 58) {
			t.Fatalf("protocol %d: excluding=%v loss=%+v", proto, got, loss)
		}
	}
}

func TestIPv6MappedSourceDoesNotProveNoTransport(t *testing.T) {
	for _, proto := range []byte{0, 43, 44, 51, 60} {
		raw := make([]byte, 48)
		raw[0], raw[5], raw[6] = 0x60, 64, proto
		copy(raw[8:24], net.ParseIP("::ffff:192.0.2.1").To16())
		copy(raw[24:40], net.ParseIP("2001:db8::2").To16())
		raw[40] = 6
		pkt := capture.DecodeIPPacket(raw)
		if !pkt.CaptureIncomplete || pkt.IPVersion != 6 {
			t.Fatal("decoder lost IP family authority", pkt)
		}
		if loss := CaptureLoss(pkt, "capture_loss"); loss.Code == "capture_unrelated" {
			t.Fatalf("IPv6 protocol %d misclassified: %+v", proto, loss)
		}
	}
}

func TestIPv6WalkableExtensionLossScope(t *testing.T) {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 0x50

	tests := []struct {
		name    string
		next    uint8
		payload []byte
	}{
		{
			name: "hop-by-hop destination options and TCP",
			next: 0,
			payload: append(
				[]byte{60, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0},
				tcp...,
			),
		},
		{
			name: "AH with TCP",
			next: 51,
			payload: append(
				[]byte{6, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				tcp...,
			),
		},
		{
			name: "first fragment with TCP",
			next: 44,
			payload: append(
				[]byte{6, 0, 0, 1, 0, 0, 0, 0}, // offset zero, more fragments set
				tcp...,
			),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkt := ipv6LossPacket(tc.next, tc.payload, 0)
			loss := CaptureLoss(pkt, "capture_truncated")
			want := evidence.LossScope{
				Source:      evidence.Endpoint{IP: "2001:db8::1", Port: 12345},
				Destination: evidence.Endpoint{IP: "2001:db8::2", Port: 443},
				Transport:   "tcp",
				Ports:       true,
			}
			if loss.Code != "capture_truncated" || loss.Scope != want {
				t.Fatalf("loss = %+v, want capture_truncated with scope %+v", loss, want)
			}
		})
	}
}

func TestIPv6WalkableMLDIsUnrelated(t *testing.T) {
	// MLDv2 report (ICMPv6 type 143) behind a Hop-by-Hop header.
	payload := []byte{58, 0, 0, 0, 0, 0, 0, 0, 143, 0, 0, 0, 0, 0, 0, 0}
	loss := CaptureLoss(ipv6LossPacket(0, payload, 0), "capture_loss")
	if loss.Code != "capture_unrelated" || loss.Scope != (evidence.LossScope{}) {
		t.Fatalf("loss = %+v, want unrelated without scope", loss)
	}
	ds := evidence.Dataset{}
	ds.RecordLoss(loss)
	if ds.LossTouches(evidence.Observation{}) {
		t.Fatal("walkable MLD excluded the learner dataset")
	}
}

func TestIPv6RoutingUDPUsesPorts(t *testing.T) {
	udp := []byte{0x9c, 0x40, 0x00, 0x35, 0, 8, 0, 0}
	payload := append([]byte{17, 0, 0, 0, 0, 0, 0, 0}, udp...)
	loss := CaptureLoss(ipv6LossPacket(43, payload, 0), "capture_truncated")
	want := evidence.LossScope{
		Source:      evidence.Endpoint{IP: "2001:db8::1", Port: 40000},
		Destination: evidence.Endpoint{IP: "2001:db8::2", Port: 53},
		Transport:   "udp",
		Ports:       true,
	}
	if loss.Code != "capture_truncated" || loss.Scope != want {
		t.Fatalf("loss = %+v, want capture_truncated with scope %+v", loss, want)
	}
}

func TestIPv6UnwalkableExtensionLossExcludesDataset(t *testing.T) {
	overBudget := make([]byte, 264)
	overBudget[0], overBudget[1] = 58, 32 // one 264-byte Hop-by-Hop header
	overHopCount := make([]byte, 9*8)
	for offset := 0; offset < len(overHopCount); offset += 8 {
		overHopCount[offset+1] = 0
	}
	overHopCount[8*8] = 58
	tests := []struct {
		name    string
		next    uint8
		payload []byte
		missing int
	}{
		{
			name:    "truncated extension",
			next:    0,
			payload: []byte{60, 1, 0, 0, 0, 0, 0, 0},
			missing: 8,
		},
		{
			name:    "malformed destination options",
			next:    60,
			payload: []byte{58, 0, 5, 10, 0, 0, 0, 0},
		},
		{
			name:    "ESP after hop-by-hop",
			next:    0,
			payload: []byte{50, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name:    "non-first fragment",
			next:    44,
			payload: []byte{6, 0, 0, 8, 0, 0, 0, 0},
		},
		{
			name:    "over byte budget",
			next:    0,
			payload: overBudget,
		},
		{
			name:    "over hop count",
			next:    0,
			payload: overHopCount,
		},
		{
			name:    "experimental header",
			next:    253,
			payload: []byte{6, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name:    "unknown terminal protocol",
			next:    0,
			payload: []byte{200, 0, 0, 0, 0, 0, 0, 0},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			loss := CaptureLoss(ipv6LossPacket(tc.next, tc.payload, tc.missing), "capture_loss")
			if loss.Scope != (evidence.LossScope{}) || loss.Code != "capture_loss" {
				t.Fatalf("loss = %+v, want unscoped capture_loss", loss)
			}
			ds := evidence.Dataset{}
			ds.RecordLoss(loss)
			if !ds.LossTouches(evidence.Observation{}) {
				t.Fatal("unwalkable extension chain did not exclude dataset")
			}
		})
	}
}

func FuzzWalkIPv6ExtensionChain(f *testing.F) {
	f.Add(uint8(0), []byte{58, 0, 0, 0, 0, 0, 0, 0})
	f.Add(uint8(51), []byte{6, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add(uint8(44), []byte{6, 0, 0, 8, 0, 0, 0, 0})
	f.Add(uint8(253), []byte{6, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, nextHeader uint8, payload []byte) {
		terminal, transport, ok := walkIPv6ExtensionChain(nextHeader, payload)
		if !ok {
			return
		}
		switch terminal {
		case 0, 43, 44, 51, 60, 50, 135, 139, 140, 253, 254:
			t.Fatalf("walk accepted opaque/extension terminal %d", terminal)
		}
		if len(transport) > len(payload) {
			t.Fatalf("transport view length %d exceeds payload %d", len(transport), len(payload))
		}
	})
}
