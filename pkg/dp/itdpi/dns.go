package itdpi

import (
	"encoding/binary"
	"strings"
	"time"

	"github.com/containd/containd/pkg/dp/dpi"
	"github.com/containd/containd/pkg/dp/flow"
)

// DNSDecoder emits minimal DNS query/response metadata.
// It supports common uncompressed QNAMEs; compressed names are skipped for now.
type DNSDecoder struct{}

func NewDNSDecoder() *DNSDecoder { return &DNSDecoder{} }

func (d *DNSDecoder) Supports(state *flow.State) bool {
	if state == nil {
		return false
	}
	// UDP=17, TCP=6, port 53.
	if state.Key.SrcPort == 53 || state.Key.DstPort == 53 {
		return state.Key.Proto == 17 || state.Key.Proto == 6
	}
	return false
}

func (d *DNSDecoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil || len(pkt.Payload) < 12 {
		return nil, nil
	}
	payload := pkt.Payload
	// TCP DNS has 2-byte length prefix.
	if pkt.Proto == "tcp" && len(payload) >= 14 {
		l := int(binary.BigEndian.Uint16(payload[0:2]))
		if l > 0 && l <= len(payload)-2 {
			payload = payload[2 : 2+l]
		}
	}
	if len(payload) < 12 {
		return nil, nil
	}

	id := binary.BigEndian.Uint16(payload[0:2])
	flags := binary.BigEndian.Uint16(payload[2:4])
	qd := binary.BigEndian.Uint16(payload[4:6])
	an := binary.BigEndian.Uint16(payload[6:8])
	// ns := binary.BigEndian.Uint16(payload[8:10])
	// ar := binary.BigEndian.Uint16(payload[10:12])

	qr := (flags & 0x8000) != 0
	rcode := uint8(flags & 0x000F)
	opcode := uint8((flags >> 11) & 0x0F)

	offset := 12
	qname := ""
	qtype := uint16(0)
	qclass := uint16(0)
	if qd > 0 {
		name, next, ok := parseQname(payload, offset)
		if ok {
			qname = name
			offset = next
			if offset+4 <= len(payload) {
				qtype = binary.BigEndian.Uint16(payload[offset : offset+2])
				qclass = binary.BigEndian.Uint16(payload[offset+2 : offset+4])
			}
		}
	}

	kind := "query"
	if qr {
		kind = "response"
	}
	attrs := map[string]any{
		"id":            id,
		"qr":            qr,
		"opcode":        opcode,
		"rcode":         rcode,
		"questions":     qd,
		"answers":       an,
		"qname":         qname,
		"qtype":         qtype,
		"qclass":        qclass,
		"transport":     pkt.Proto,
		"src_port":      pkt.SrcPort,
		"dst_port":      pkt.DstPort,
	}
	ev := dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "dns",
		Kind:       kind,
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
	return []dpi.Event{ev}, nil
}

func (d *DNSDecoder) OnFlowEnd(state *flow.State) ([]dpi.Event, error) { return nil, nil }

func parseQname(buf []byte, off int) (string, int, bool) {
	labels := make([]string, 0, 4)
	for {
		if off >= len(buf) {
			return "", off, false
		}
		l := int(buf[off])
		off++
		if l == 0 {
			break
		}
		// compression pointer not supported in Phase 1.
		if l&0xC0 != 0 {
			return "", off, false
		}
		if off+l > len(buf) {
			return "", off, false
		}
		labels = append(labels, string(buf[off:off+l]))
		off += l
	}
	return strings.ToLower(strings.Join(labels, ".")), off, true
}

