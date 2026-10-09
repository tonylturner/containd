// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package capture

import (
	"encoding/binary"
	"net"
)

// Packet.Invalid reasons.
const (
	InvalidTruncated = "truncated"  // shorter than its IP header
	InvalidIPVersion = "ip_version" // neither IPv4 nor IPv6
	InvalidIPHeader  = "ip_header"  // IPv4 IHL below 20 bytes
	InvalidFragment  = "fragment"   // IPv4 MF/fragment offset or IPv6 fragment header
	InvalidIPv6      = "ipv6"       // IPv6 extension header chain (not walked)
	InvalidProtocol  = "protocol"   // transport is neither TCP nor UDP
	InvalidTCPHeader = "tcp_header" // TCP header short or bad data offset
	InvalidUDPHeader = "udp_header" // UDP header short
)

// DecodeIPPacket decodes a raw IP packet (no link-layer header). It never
// fails silently: a packet that cannot be decoded has Invalid set, and its
// tuple fields are best effort. Timestamp and Interface are left to the
// caller.
func DecodeIPPacket(data []byte) Packet {
	pkt, _ := decodeIP(data)
	return pkt
}

// decodeIP decodes like DecodeIPPacket and also reports whether capture
// delivers the packet to its handler. Capture still accepts undecodable
// packets itself; IPv4 fragments that decode are delivered as before, now
// marked Invalid=fragment.
func decodeIP(data []byte) (Packet, bool) {
	if len(data) < 1 {
		return Packet{Invalid: InvalidTruncated}, false
	}
	switch data[0] >> 4 {
	case 4:
		return decodeIPv4Raw(data)
	case 6:
		return decodeIPv6Raw(data)
	default:
		return Packet{Invalid: InvalidIPVersion}, false
	}
}

func decodeIPv4Raw(data []byte) (Packet, bool) {
	if len(data) < 20 {
		return Packet{Invalid: InvalidTruncated}, false
	}
	pkt := Packet{
		Proto: data[9],
		SrcIP: net.IPv4(data[12], data[13], data[14], data[15]),
		DstIP: net.IPv4(data[16], data[17], data[18], data[19]),
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 {
		pkt.Invalid = InvalidIPHeader
		return pkt, false
	}
	if len(data) < ihl {
		pkt.Invalid = InvalidTruncated
		return pkt, false
	}
	ok := decodeL4(&pkt, data[ihl:])
	const moreFragments, offsetMask = 0x2000, 0x1fff
	if frag := binary.BigEndian.Uint16(data[6:8]); ok && frag&(moreFragments|offsetMask) != 0 {
		pkt.Invalid = InvalidFragment
	}
	return pkt, ok
}

func decodeIPv6Raw(data []byte) (Packet, bool) {
	if len(data) < 40 {
		return Packet{Invalid: InvalidTruncated}, false
	}
	pkt := Packet{
		Proto: data[6],
		SrcIP: net.IP(append([]byte(nil), data[8:24]...)),
		DstIP: net.IP(append([]byte(nil), data[24:40]...)),
	}
	switch pkt.Proto {
	case 44:
		pkt.Invalid = InvalidFragment
		return pkt, false
	case 0, 43, 51, 60, 135, 139, 140, 253, 254:
		pkt.Invalid = InvalidIPv6
		return pkt, false
	}
	return pkt, decodeL4(&pkt, data[40:])
}

// decodeL4 fills the transport fields of pkt and reports success; on
// failure it sets pkt.Invalid.
func decodeL4(pkt *Packet, data []byte) bool {
	switch pkt.Proto {
	case 6:
		pkt.Transport = "tcp"
		return decodeTCP(pkt, data)
	case 17:
		pkt.Transport = "udp"
		return decodeUDP(pkt, data)
	default:
		pkt.Invalid = InvalidProtocol
		return false
	}
}

func decodeTCP(pkt *Packet, data []byte) bool {
	if len(data) >= 4 {
		pkt.SrcPort = binary.BigEndian.Uint16(data[0:2])
		pkt.DstPort = binary.BigEndian.Uint16(data[2:4])
	}
	if len(data) < 20 {
		pkt.Invalid = InvalidTCPHeader
		return false
	}
	off := int(data[12]>>4) * 4
	if off < 20 || len(data) < off {
		pkt.Invalid = InvalidTCPHeader
		return false
	}
	pkt.TCP = TCPMeta{
		Valid:  true,
		Seq:    binary.BigEndian.Uint32(data[4:8]),
		Ack:    binary.BigEndian.Uint32(data[8:12]),
		Flags:  TCPFlags(data[13]),
		Window: binary.BigEndian.Uint16(data[14:16]),
	}
	pkt.Payload = append([]byte(nil), data[off:]...)
	return true
}

func decodeUDP(pkt *Packet, data []byte) bool {
	if len(data) < 8 {
		pkt.Invalid = InvalidUDPHeader
		return false
	}
	pkt.SrcPort = binary.BigEndian.Uint16(data[0:2])
	pkt.DstPort = binary.BigEndian.Uint16(data[2:4])
	pkt.Payload = append([]byte(nil), data[8:]...)
	return true
}
