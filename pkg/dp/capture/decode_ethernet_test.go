// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"bytes"
	"testing"
)

func TestDecodeEthernetFrame(t *testing.T) {
	raw := tcpIPv4Packet(7, 0x18, []byte{1, 2}, 4)
	for _, tags := range []int{0, 1, 2, 3} {
		frame := make([]byte, 14)
		frame[12] = 8
		for range tags {
			frame = append(frame[:12], append([]byte{0x88, 0xa8, 0, 1}, frame[12:]...)...)
		}
		frame = append(frame, raw...)
		p, ok := DecodeEthernetFrame(frame)
		if !ok || p.Interface != "" || !p.Timestamp.IsZero() || p.SrcPort != 40000 || p.DstPort != 502 || !bytes.Equal(p.Payload, []byte{1, 2}) {
			t.Fatalf("tags=%d: %v %+v", tags, ok, p)
		}
	}
}

func TestDecodeEthernetFrameRejectsLinkAndVersion(t *testing.T) {
	for _, data := range [][]byte{nil, make([]byte, 13), make([]byte, 14),
		append(make([]byte, 12), 0x81, 0, 0),
		append(append(make([]byte, 12), 0x86, 0xdd), tcpIPv4Packet(1, 0, nil, 4)...)} {
		if _, ok := DecodeEthernetFrame(data); ok {
			t.Fatalf("accepted %x", data)
		}
	}
}

func TestDecodeEthernetFramePreservesTrustedLoss(t *testing.T) {
	frame := make([]byte, 14)
	frame[12] = 8
	frame = append(frame, tcpIPv4Packet(7, 0x18, nil, 4)[:24]...)
	p, ok := DecodeEthernetFrame(frame)
	if !ok || !p.CaptureIncomplete || !p.PortsValid || p.Invalid == "" {
		t.Fatalf("lost incomplete packet: %v %+v", ok, p)
	}
}
