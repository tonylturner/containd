// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package capture

import (
	"encoding/binary"
	"net"
	"time"
)

// decodeIPPacket decodes a raw IP packet (no Ethernet header) into a Packet.
// This is used by NFQUEUE which delivers IP-layer packets directly.
func decodeIPPacket(data []byte) (Packet, bool) {
	return decodeIP("nfqueue", data)
}

// decodeIP decodes an IPv4 or IPv6 packet captured on iface. NFQUEUE, NFLOG
// and AF_PACKET (after the link header) all share this decoder.
func decodeIP(iface string, data []byte) (Packet, bool) {
	if len(data) < 1 {
		return Packet{}, false
	}
	version := data[0] >> 4
	switch version {
	case 4:
		return decodeIPv4Raw(iface, data)
	case 6:
		return decodeIPv6Raw(iface, data)
	default:
		return Packet{}, false
	}
}

func decodeIPv4Raw(iface string, data []byte) (Packet, bool) {
	if len(data) < 20 {
		return Packet{}, false
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl {
		return Packet{}, false
	}
	// Bound the packet by the IP total length so link-layer padding on
	// short frames (Ethernet pads to 60 bytes) never reads as L4 payload.
	// A zero or oversized total length (TSO/GRO, snaplen truncation)
	// leaves the captured bytes as they are.
	if total := int(binary.BigEndian.Uint16(data[2:4])); total >= ihl && total < len(data) {
		data = data[:total]
	}
	proto := data[9]
	src := net.IPv4(data[12], data[13], data[14], data[15])
	dst := net.IPv4(data[16], data[17], data[18], data[19])
	return decodeL4(iface, proto, src, dst, data[ihl:])
}

func decodeIPv6Raw(iface string, data []byte) (Packet, bool) {
	if len(data) < 40 {
		return Packet{}, false
	}
	// Same padding bound as IPv4; a zero payload length is a jumbogram.
	if payloadLen := int(binary.BigEndian.Uint16(data[4:6])); payloadLen > 0 && 40+payloadLen < len(data) {
		data = data[:40+payloadLen]
	}
	proto := data[6]
	src := net.IP(append([]byte(nil), data[8:24]...))
	dst := net.IP(append([]byte(nil), data[24:40]...))
	return decodeL4(iface, proto, src, dst, data[40:])
}

func decodeL4(iface string, proto uint8, src, dst net.IP, data []byte) (Packet, bool) {
	switch proto {
	case 6: // TCP
		if len(data) < 20 {
			return Packet{}, false
		}
		sport := binary.BigEndian.Uint16(data[0:2])
		dport := binary.BigEndian.Uint16(data[2:4])
		off := int(data[12]>>4) * 4
		if off < 20 || len(data) < off {
			return Packet{}, false
		}
		seq := binary.BigEndian.Uint32(data[4:8])
		flags := data[13]
		if flags&TCPFlagSYN != 0 {
			// The SYN occupies the first sequence number; any data on a
			// SYN (TCP Fast Open) starts one past it.
			seq++
		}
		payload := append([]byte(nil), data[off:]...)
		return Packet{
			Timestamp: time.Now().UTC(),
			Interface: iface,
			SrcIP:     src,
			DstIP:     dst,
			SrcPort:   sport,
			DstPort:   dport,
			Proto:     proto,
			Transport: "tcp",
			Payload:   payload,
			TCPSeq:    seq,
			HasTCPSeq: true,
			TCPFlags:  flags,
		}, true
	case 17: // UDP
		if len(data) < 8 {
			return Packet{}, false
		}
		sport := binary.BigEndian.Uint16(data[0:2])
		dport := binary.BigEndian.Uint16(data[2:4])
		payload := append([]byte(nil), data[8:]...)
		return Packet{
			Timestamp: time.Now().UTC(),
			Interface: iface,
			SrcIP:     src,
			DstIP:     dst,
			SrcPort:   sport,
			DstPort:   dport,
			Proto:     proto,
			Transport: "udp",
			Payload:   payload,
		}, true
	default:
		return Packet{}, false
	}
}
