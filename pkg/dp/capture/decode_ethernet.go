// SPDX-License-Identifier: Apache-2.0

package capture

import "encoding/binary"

// DecodeEthernetFrame decodes Ethernet with zero or more 802.1Q/802.1ad tags.
// The EtherType must agree with the IP version. Observationally eligible
// fragments and trusted incomplete IP packets are delivered with Invalid set;
// callers must not interpret their payload as complete application data.
// Timestamp and Interface are left to the caller. Checksums are not verified.
func DecodeEthernetFrame(data []byte) (Packet, bool) {
	if len(data) < 14 {
		return Packet{}, false
	}
	typ := binary.BigEndian.Uint16(data[12:14])
	data = data[14:]
	for typ == 0x8100 || typ == 0x88a8 {
		if len(data) < 4 {
			return Packet{}, false
		}
		typ = binary.BigEndian.Uint16(data[2:4])
		data = data[4:]
	}
	var version byte
	switch typ {
	case 0x0800:
		version = 4
	case 0x86dd:
		version = 6
	default:
		return Packet{}, false
	}
	if len(data) == 0 || data[0]>>4 != version {
		return Packet{}, false
	}
	pkt, ok := decodeIP(data)
	return pkt, ok || pkt.CaptureIncomplete
}
