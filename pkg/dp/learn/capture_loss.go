// SPDX-License-Identifier: Apache-2.0
package learn

import (
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/evidence"
)

// CaptureLoss uses only decoded wire coordinates, never observation timestamps.
// Opaque IPv6 extension chains can contain TCP/UDP and must stay excluding.
func CaptureLoss(pkt capture.Packet, code string) evidence.CollectionLoss {
	loss := evidence.CollectionLoss{Code: code}
	if pkt.SrcIP == nil || pkt.DstIP == nil || pkt.Invalid == capture.InvalidIPHeader {
		return loss
	}
	switch pkt.Proto {
	case 6, 17:
		transport := "tcp"
		if pkt.Proto == 17 {
			transport = "udp"
		}
		loss.Scope = evidence.LossScope{
			Source:      evidence.Endpoint{IP: pkt.SrcIP.String(), Port: pkt.SrcPort},
			Destination: evidence.Endpoint{IP: pkt.DstIP.String(), Port: pkt.DstPort},
			Transport:   transport, Ports: pkt.PortsValid || pkt.TCP.Valid,
		}
	case 0, 43, 44, 51, 60, 135, 139, 140, 253, 254:
		// Without walking the extension chain, no transport is proven absent.
		if pkt.IPVersion == 4 {
			loss.Code = "capture_unrelated"
		}
	default:
		loss.Code = "capture_unrelated"
	}
	return loss
}
