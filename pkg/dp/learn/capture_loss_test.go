// SPDX-License-Identifier: Apache-2.0
package learn

import (
	"net"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/evidence"
)

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
