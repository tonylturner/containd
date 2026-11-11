// SPDX-License-Identifier: Apache-2.0
package learn

import (
	"encoding/binary"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/evidence"
)

const (
	maxIPv6ExtensionHeaders = 8
	maxIPv6ExtensionBytes   = 256
)

// CaptureLoss uses only decoded wire coordinates, never observation timestamps.
// IPv6 extension chains are walked for at most eight headers and 256 bytes.
func CaptureLoss(pkt capture.Packet, code string) evidence.CollectionLoss {
	loss := evidence.CollectionLoss{Code: code}
	if pkt.Token.Inline() {
		loss.CaptureHook = evidence.CaptureNFQueue
	}
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
	case 0, 43, 44, 51, 60:
		if pkt.IPVersion == 6 {
			proto, transportData, ok := walkIPv6ExtensionChain(pkt.Proto, pkt.IPv6Payload)
			if !ok {
				return loss
			}
			switch proto {
			case 6, 17:
				setTransportScope(&loss, pkt, proto, transportData)
			case 50, 135, 139, 140, 253, 254:
				// ESP and extension headers outside the supported walk are
				// unknowable, so no unrelated-traffic claim is sound.
			default:
				if !knownNonTCPUDPProtocol(proto) {
					return loss
				}
				loss.Code = "capture_unrelated"
			}
			return loss
		}
		if pkt.IPVersion == 4 {
			loss.Code = "capture_unrelated"
		}
	case 50, 135, 139, 140, 253, 254:
		// ESP and unsupported/experimental IPv6 headers can conceal transport.
		if pkt.IPVersion == 4 {
			loss.Code = "capture_unrelated"
		}
	default:
		loss.Code = "capture_unrelated"
	}
	return loss
}

func knownNonTCPUDPProtocol(proto uint8) bool {
	switch proto {
	case 1, 2, 4, 33, 41, 47, 58, 59, 89, 94, 97, 98, 103, 111, 112, 113, 115, 124, 132, 133, 136, 137, 138, 142, 143, 145, 146:
		return true
	default:
		return false
	}
}

func setTransportScope(loss *evidence.CollectionLoss, pkt capture.Packet, proto uint8, data []byte) {
	transport := "tcp"
	if proto == 17 {
		transport = "udp"
	}
	ports := len(data) >= 4
	var sourcePort, destinationPort uint16
	if ports {
		sourcePort = binary.BigEndian.Uint16(data[0:2])
		destinationPort = binary.BigEndian.Uint16(data[2:4])
	}
	loss.Scope = evidence.LossScope{
		Source:      evidence.Endpoint{IP: pkt.SrcIP.String(), Port: sourcePort},
		Destination: evidence.Endpoint{IP: pkt.DstIP.String(), Port: destinationPort},
		Transport:   transport,
		Ports:       ports,
	}
}

// walkIPv6ExtensionChain returns the terminal next-header value and its
// captured bytes. False means the chain cannot be walked without guessing.
func walkIPv6ExtensionChain(nextHeader uint8, payload []byte) (uint8, []byte, bool) {
	offset, headers := 0, 0
	for {
		var length int
		switch nextHeader {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			if headers >= maxIPv6ExtensionHeaders ||
				offset > maxIPv6ExtensionBytes-2 ||
				len(payload)-offset < 2 {
				return 0, nil, false
			}
			length = (int(payload[offset+1]) + 1) * 8
		case 44: // Fragment
			if headers >= maxIPv6ExtensionHeaders ||
				offset > maxIPv6ExtensionBytes-8 ||
				len(payload)-offset < 8 {
				return 0, nil, false
			}
			fragment := binary.BigEndian.Uint16(payload[offset+2 : offset+4])
			if fragment&0xfff8 != 0 || fragment&0x0006 != 0 {
				return 0, nil, false
			}
			length = 8
		case 51: // Authentication Header
			if headers >= maxIPv6ExtensionHeaders ||
				offset > maxIPv6ExtensionBytes-8 ||
				len(payload)-offset < 8 {
				return 0, nil, false
			}
			if payload[offset+2] != 0 || payload[offset+3] != 0 {
				return 0, nil, false
			}
			length = (int(payload[offset+1]) + 2) * 4
		default:
			if opaqueIPv6Header(nextHeader) {
				return 0, nil, false
			}
			return nextHeader, payload[offset:], true
		}

		if headers >= maxIPv6ExtensionHeaders ||
			length > maxIPv6ExtensionBytes-offset ||
			length > len(payload)-offset {
			return 0, nil, false
		}
		if (nextHeader == 0 || nextHeader == 60) &&
			!validIPv6OptionsHeader(payload[offset:offset+length]) {
			return 0, nil, false
		}
		nextHeader = payload[offset]
		offset += length
		headers++
	}
}

func validIPv6OptionsHeader(header []byte) bool {
	for offset := 2; offset < len(header); {
		if header[offset] == 0 { // Pad1
			offset++
			continue
		}
		if len(header)-offset < 2 {
			return false
		}
		length := int(header[offset+1])
		if length > len(header)-offset-2 {
			return false
		}
		offset += 2 + length
	}
	return true
}

func opaqueIPv6Header(proto uint8) bool {
	switch proto {
	case 50, 135, 139, 140, 253, 254:
		return true
	default:
		return false
	}
}
