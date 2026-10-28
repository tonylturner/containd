// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package corpus

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
)

const (
	MaxCaptureBytes = 32 << 20
	MaxPackets      = 100000
	MaxPacketBytes  = 65549 // Ethernet + maximum IPv4 datagram
)

// SourceSpan attributes transport payload bytes [Start,End) to an original
// capture record (one-based Frame). Controls have an empty [0,0) span.
type SourceSpan struct {
	Capture           string
	Frame, Start, End int
}

// Packet owns its wire bytes, decoded payload and provenance. Transforms clear
// Wire: generated Manager inputs are not serializable packet captures.
type Packet struct {
	Source     []SourceSpan
	Time       time.Time
	Wire       []byte
	Decoded    capture.Packet
	Connection string
	Dir        dpi.StreamDir
	Origin     uint32
	HasOrigin  bool
}

type SkippedRecord struct {
	Frame  int
	Reason string
}
type ReadOptions struct{ IgnoreEtherTypes []uint16 }

// ReadPCAP reads classic microsecond or nanosecond pcap 2.4 in either byte
// order. It never deduplicates, reorders or reassembles transport data.
func ReadPCAP(r io.Reader, name string, opts ReadOptions) ([]Packet, []SkippedRecord, error) {
	r = io.LimitReader(r, MaxCaptureBytes+1)
	var h [24]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, nil, fmt.Errorf("pcap header: %w", err)
	}
	var order binary.ByteOrder
	nano := false
	switch string(h[:4]) {
	case "\xd4\xc3\xb2\xa1":
		order = binary.LittleEndian
	case "\xa1\xb2\xc3\xd4":
		order = binary.BigEndian
	case "\x4d\x3c\xb2\xa1":
		order = binary.LittleEndian
		nano = true
	case "\xa1\xb2\x3c\x4d":
		order = binary.BigEndian
		nano = true
	case "\x0a\x0d\x0d\x0a":
		return nil, nil, fmt.Errorf("pcapng is unsupported")
	default:
		return nil, nil, fmt.Errorf("unsupported pcap magic")
	}
	snap := order.Uint32(h[16:20])
	if order.Uint16(h[4:6]) != 2 || order.Uint16(h[6:8]) != 4 || order.Uint32(h[20:24]) != 1 || snap == 0 {
		return nil, nil, fmt.Errorf("unsupported pcap version, linktype or snaplen")
	}
	var packets []Packet
	var skipped []SkippedRecord
	total := 24
	for frame := 1; ; frame++ {
		var rh [16]byte
		n, err := io.ReadFull(r, rh[:])
		if err == io.EOF && n == 0 {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("frame %d record: %w", frame, err)
		}
		size, wire := order.Uint32(rh[8:12]), order.Uint32(rh[12:16])
		total += 16 + int(size)
		if frame > MaxPackets || size != wire || size < 14 || size > snap || size > MaxPacketBytes || total > MaxCaptureBytes {
			return nil, nil, fmt.Errorf("frame %d truncated or exceeds bounds", frame)
		}
		raw := make([]byte, int(size))
		if _, err := io.ReadFull(r, raw); err != nil {
			return nil, nil, fmt.Errorf("frame %d bytes: %w", frame, err)
		}
		frac := order.Uint32(rh[4:8])
		limit := uint32(1000000)
		scale := int64(1000)
		if nano {
			limit = 1000000000
			scale = 1
		}
		if frac >= limit {
			return nil, nil, fmt.Errorf("frame %d invalid timestamp", frame)
		}
		ts := time.Unix(int64(order.Uint32(rh[:4])), int64(frac)*scale).UTC()
		ether := binary.BigEndian.Uint16(raw[12:14])
		// IPv6 is always rejected, even if accidentally listed as ignorable.
		if ether == 0x86dd {
			return nil, nil, fmt.Errorf("frame %d IPv6 unsupported", frame)
		}
		if ether != 0x0800 {
			ignored := false
			for _, v := range opts.IgnoreEtherTypes {
				if v == ether {
					ignored = true
				}
			}
			if !ignored {
				return nil, nil, fmt.Errorf("frame %d unsupported EtherType %#x", frame, ether)
			}
			skipped = append(skipped, SkippedRecord{frame, fmt.Sprintf("ignored EtherType %#x", ether)})
			continue
		}
		dec, err := decodeIPv4(raw[14:], ts)
		if err != nil {
			return nil, nil, fmt.Errorf("frame %d: %w", frame, err)
		}
		packets = append(packets, Packet{Source: []SourceSpan{{name, frame, 0, len(dec.Payload)}}, Time: ts, Wire: raw, Decoded: dec})
	}
	if len(packets) == 0 {
		return nil, nil, fmt.Errorf("empty capture")
	}
	return packets, skipped, nil
}

// This deliberately does not use the production capture decoder. Checksums
// are retained, not certified: offload artifacts require manifest disclosure.
func decodeIPv4(b []byte, ts time.Time) (capture.Packet, error) {
	p := capture.Packet{Timestamp: ts}
	if len(b) < 20 || b[0]>>4 != 4 {
		return p, fmt.Errorf("invalid IPv4 header")
	}
	ihl := int(b[0]&15) * 4
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if ihl < 20 || ihl > len(b) || total < ihl || total > len(b) {
		return p, fmt.Errorf("truncated IPv4")
	}
	if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
		return p, fmt.Errorf("IPv4 fragments unsupported")
	}
	p.SrcIP = append([]byte(nil), b[12:16]...)
	p.DstIP = append([]byte(nil), b[16:20]...)
	p.Proto = b[9]
	t := b[ihl:total]
	if len(t) < 8 {
		return p, fmt.Errorf("truncated transport header")
	}
	p.SrcPort = binary.BigEndian.Uint16(t[:2])
	p.DstPort = binary.BigEndian.Uint16(t[2:4])
	switch p.Proto {
	case 6:
		if len(t) < 20 {
			return p, fmt.Errorf("truncated TCP")
		}
		off := int(t[12]>>4) * 4
		if off < 20 || off > len(t) {
			return p, fmt.Errorf("invalid TCP header length")
		}
		p.Transport = "tcp"
		p.TCP = capture.TCPMeta{Valid: true, Seq: binary.BigEndian.Uint32(t[4:8]), Ack: binary.BigEndian.Uint32(t[8:12]), Flags: capture.TCPFlags(t[13]), Window: binary.BigEndian.Uint16(t[14:16])}
		p.Payload = append([]byte(nil), t[off:]...)
	case 17:
		if int(binary.BigEndian.Uint16(t[4:6])) != len(t) {
			return p, fmt.Errorf("invalid UDP length")
		}
		p.Transport = "udp"
		p.Payload = append([]byte(nil), t[8:]...)
	default:
		return p, fmt.Errorf("unsupported IPv4 transport %d", p.Proto)
	}
	return p, nil
}
