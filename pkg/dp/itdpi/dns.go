// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package itdpi

import (
	"encoding/binary"
	"net/netip"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// DNSDecoder emits minimal DNS query/response metadata.
// Supports both uncompressed and compressed (RFC 1035 §4.1.4) QNAMEs.
type DNSDecoder struct{}

func NewDNSDecoder() *DNSDecoder { return &DNSDecoder{} }

// Ports implements dpi.PortHinter for port-based dispatch.
func (d *DNSDecoder) Ports() (tcpPorts, udpPorts []uint16) {
	return []uint16{53}, []uint16{53}
}

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
		"id":        id,
		"qr":        qr,
		"opcode":    opcode,
		"rcode":     rcode,
		"questions": qd,
		"answers":   an,
		"qname":     qname,
		"qtype":     qtype,
		"qclass":    qclass,
		"transport": pkt.Proto,
		"src_port":  pkt.SrcPort,
		"dst_port":  pkt.DstPort,
	}
	ev := dpi.Event{
		FlowID:     state.ID(),
		Proto:      "dns",
		Kind:       kind,
		Attributes: attrs,
	}
	return []dpi.Event{ev}, nil
}

func (d *DNSDecoder) OnFlowEnd(state *flow.State) ([]dpi.Event, error) { return nil, nil }

// DNSAnswer associates a question or its CNAME target with an address. TTL is
// the minimum TTL on the path from Name to that address, in seconds.
type DNSAnswer struct {
	Name string
	IP   netip.Addr
	TTL  uint32
}

type dnsRecord struct {
	name, target string
	ip           netip.Addr
	ttl          uint32
}

// DNSAnswers reads complete, successful standard responses. Only answer-section
// addresses reachable from an IN question are returned; additional records do
// not create associations. TCP input must contain its complete length prefix.
// This packet-local parser does not reassemble TCP streams.
func DNSAnswers(payload []byte, tcp bool) []DNSAnswer {
	if tcp {
		var out []DNSAnswer
		for len(payload) >= 2 {
			n := int(binary.BigEndian.Uint16(payload))
			if n == 0 || n > len(payload)-2 {
				break
			}
			out = append(out, DNSAnswers(payload[2:2+n], false)...)
			payload = payload[2+n:]
		}
		return out
	}
	if len(payload) < 12 {
		return nil
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0xFA0F != 0x8000 { // QR, opcode, TC, rcode
		return nil
	}
	qd := int(binary.BigEndian.Uint16(payload[4:6]))
	an := int(binary.BigEndian.Uint16(payload[6:8]))
	off := 12
	var questions []string
	for range qd {
		name, next, ok := parseQname(payload, off)
		if !ok || next+4 > len(payload) {
			return nil
		}
		if binary.BigEndian.Uint16(payload[next+2:next+4]) == 1 {
			questions = append(questions, name)
		}
		off = next + 4
	}
	records := make(map[string][]dnsRecord)
	for range an {
		name, next, ok := parseQname(payload, off)
		if !ok || next+10 > len(payload) {
			return nil
		}
		typ := binary.BigEndian.Uint16(payload[next : next+2])
		class := binary.BigEndian.Uint16(payload[next+2 : next+4])
		ttl := binary.BigEndian.Uint32(payload[next+4 : next+8])
		n := int(binary.BigEndian.Uint16(payload[next+8 : next+10]))
		off = next + 10
		end := off + n
		if end > len(payload) {
			return nil
		}
		r := dnsRecord{name: name, ttl: ttl}
		if class == 1 {
			switch {
			case typ == 1 && n == 4, typ == 28 && n == 16:
				r.ip, _ = netip.AddrFromSlice(payload[off:end])
			case typ == 5:
				target, after, valid := parseQname(payload, off)
				if !valid || after != end {
					return nil
				}
				r.target = target
			}
			if r.ip.IsValid() || r.target != "" {
				records[name] = append(records[name], r)
			}
		}
		off = end
	}
	var out []DNSAnswer
	for _, q := range questions {
		out = append(out, resolveDNSAnswers(q, records)...)
	}
	return out
}

func resolveDNSAnswers(q string, records map[string][]dnsRecord) []DNSAnswer {
	// CNAME owners have a single target. Reject ambiguous owners and cycles
	// rather than treating unrelated answer records as trusted associations.
	var path []dnsRecord
	seen := make(map[string]bool)
	name := q
	for !seen[name] {
		seen[name] = true
		rrs := records[name]
		if len(rrs) == 0 {
			return nil
		}
		if rrs[0].target != "" {
			if len(rrs) != 1 {
				return nil
			}
			path = append(path, rrs[0])
			name = rrs[0].target
			continue
		}
		var out []DNSAnswer
		for _, r := range rrs {
			if !r.ip.IsValid() || r.target != "" {
				return nil
			}
			out = append(out, DNSAnswer{Name: name, IP: r.ip.Unmap(), TTL: r.ttl})
			ttl := r.ttl
			for i := len(path) - 1; i >= 0; i-- {
				ttl = min(ttl, path[i].ttl)
				out = append(out, DNSAnswer{Name: path[i].name, IP: r.ip.Unmap(), TTL: ttl})
			}
		}
		return out
	}
	return nil
}

// parseQname parses a DNS name starting at off, handling both inline labels
// and compression pointers (RFC 1035 §4.1.4). It returns the name, the offset
// just past the name field in the original position, and success.
func parseQname(buf []byte, off int) (string, int, bool) {
	const maxNameLen = 255
	const maxPointers = 10

	// nameBuf accumulates the decoded name to avoid join allocations.
	var nameBuf [maxNameLen + 1]byte
	nameLen := 0

	cur := off   // current read position (follows pointers)
	endOff := -1 // original stream offset after the name field
	ptrCount := 0
	followed := false

	for {
		if cur < 0 || cur >= len(buf) {
			return "", off, false
		}
		labelLen := int(buf[cur])

		if labelLen == 0 {
			// Root label — end of name.
			if !followed {
				endOff = cur + 1
			}
			break
		}

		// Check for compression pointer: top two bits set.
		if labelLen&0xC0 == 0xC0 {
			if cur+1 >= len(buf) {
				return "", off, false
			}
			ptrCount++
			if ptrCount > maxPointers {
				return "", off, false // loop detection
			}
			if !followed {
				endOff = cur + 2 // original stream advances past the 2-byte pointer
				followed = true
			}
			ptr := int(binary.BigEndian.Uint16(buf[cur:cur+2])) & 0x3FFF
			if ptr >= cur {
				// Forward pointers are invalid (would cause loops).
				return "", off, false
			}
			cur = ptr
			continue
		}

		// Regular label.
		if labelLen > 63 {
			return "", off, false
		}
		cur++
		if cur+labelLen > len(buf) {
			return "", off, false
		}
		// Add dot separator before this label (if not first).
		if nameLen > 0 {
			if nameLen >= maxNameLen {
				return "", off, false
			}
			nameBuf[nameLen] = '.'
			nameLen++
		}
		if nameLen+labelLen > maxNameLen {
			return "", off, false
		}
		copy(nameBuf[nameLen:], buf[cur:cur+labelLen])
		nameLen += labelLen
		cur += labelLen
	}

	if endOff < 0 {
		endOff = cur + 1
	}

	// Lower-case in place (ASCII only, valid for DNS labels).
	for i := 0; i < nameLen; i++ {
		c := nameBuf[i]
		if c >= 'A' && c <= 'Z' {
			nameBuf[i] = c + 32
		}
	}

	return string(nameBuf[:nameLen]), endOff, true
}
