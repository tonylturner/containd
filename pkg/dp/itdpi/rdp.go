// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package itdpi

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// RDPDecoder parses RDP connection sequences including TPKT/X.224 negotiation,
// security protocol selection, and cookie extraction.
type RDPDecoder struct{}

func NewRDPDecoder() *RDPDecoder { return &RDPDecoder{} }

// Ports implements dpi.PortHinter for port-based dispatch.
func (d *RDPDecoder) Ports() (tcpPorts, udpPorts []uint16) {
	return []uint16{3389}, nil
}

func (d *RDPDecoder) Supports(state *flow.State) bool {
	if state == nil || state.Key.Proto != 6 {
		return false
	}
	switch state.Key.SrcPort {
	case 3389:
		return true
	}
	switch state.Key.DstPort {
	case 3389:
		return true
	}
	return false
}

// RDP X.224 COTP type codes.
const (
	x224ConnectionRequest = 0xE0
	x224ConnectionConfirm = 0xC0
)

// RDP negotiation type codes.
const (
	rdpNegReq  = 0x01
	rdpNegResp = 0x02
)

// RDP requested protocol flags.
const (
	rdpProtoStandard     = 0x00
	rdpProtoTLS          = 0x01
	rdpProtoCredSSP      = 0x02
	rdpProtoRDSTLS       = 0x04
	rdpProtoCredSSPEarly = 0x08
)

// maxCookieLen caps cookie extraction to prevent unbounded reads.
const maxCookieLen = 256

var cookiePrefix = []byte("Cookie: mstshash=")

func (d *RDPDecoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil || len(pkt.Payload) == 0 {
		return nil, nil
	}

	p := pkt.Payload

	// Parse TPKT header: version(1) + reserved(1) + length(2).
	if len(p) < 4 {
		return nil, nil
	}
	if p[0] != 0x03 { // TPKT version must be 3
		return nil, nil
	}
	tpktLen := int(binary.BigEndian.Uint16(p[2:4]))
	if tpktLen < 7 || tpktLen > len(p) {
		return nil, nil
	}

	// Parse X.224 COTP header at offset 4.
	// length indicator (1 byte), type code (1 byte).
	cotpLI := p[4]                   // length indicator
	cotpType := p[5] & 0xF0         // type is upper nibble
	_ = cotpLI

	if int(cotpLI)+5 > tpktLen {
		return nil, nil
	}

	switch cotpType {
	case x224ConnectionRequest:
		return d.parseConnectionRequest(state, pkt, p, tpktLen)
	case x224ConnectionConfirm:
		return d.parseConnectionConfirm(state, pkt, p, tpktLen)
	}

	// Check for MCS Connect Initial (BER tag 0x7F 0x65) after TPKT+COTP.
	cotpEnd := 4 + 1 + int(cotpLI)
	if cotpEnd+2 <= tpktLen && p[cotpEnd] == 0x7F && p[cotpEnd+1] == 0x65 {
		return d.parseMCSConnectInitial(state, pkt)
	}

	return nil, nil
}

func (d *RDPDecoder) OnFlowEnd(state *flow.State) ([]dpi.Event, error) { return nil, nil }

// parseConnectionRequest handles X.224 Connection Request (0xE0).
func (d *RDPDecoder) parseConnectionRequest(state *flow.State, pkt *dpi.ParsedPacket, p []byte, tpktLen int) ([]dpi.Event, error) {
	// X.224 CR-TPDU: LI(1) + type(1) + dst-ref(2) + src-ref(2) + class(1) = 7 bytes header.
	// Data starts at offset 4 (TPKT) + 7 (X.224 fixed) = 11.
	attrs := map[string]any{
		"stage":     "connection_request",
		"src_port":  pkt.SrcPort,
		"dst_port":  pkt.DstPort,
		"transport": pkt.Proto,
	}

	dataStart := 11
	if dataStart < tpktLen {
		data := p[dataStart:tpktLen]

		// Extract cookie if present.
		if cookie := extractCookie(data); cookie != "" {
			attrs["cookie"] = cookie
		}

		// Look for RDP Negotiation Request at the end.
		negReqOff := findNegReq(data)
		if negReqOff >= 0 && negReqOff+8 <= len(data) {
			neg := data[negReqOff:]
			if neg[0] == rdpNegReq && neg[1] == 0x00 {
				// length is at bytes 2-3 (little-endian, should be 8)
				negLen := binary.LittleEndian.Uint16(neg[2:4])
				if negLen == 8 && negReqOff+8 <= len(data) {
					reqProto := binary.LittleEndian.Uint32(neg[4:8])
					protos, secLevel := decodeRequestedProtocols(reqProto)
					attrs["requested_protocols"] = protos
					attrs["security_level"] = secLevel
				}
			}
		}
	}

	ev := dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "rdp",
		Kind:       "connection_request",
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
	return []dpi.Event{ev}, nil
}

// parseConnectionConfirm handles X.224 Connection Confirm (0xC0).
func (d *RDPDecoder) parseConnectionConfirm(state *flow.State, pkt *dpi.ParsedPacket, p []byte, tpktLen int) ([]dpi.Event, error) {
	attrs := map[string]any{
		"stage":     "connection_confirm",
		"src_port":  pkt.SrcPort,
		"dst_port":  pkt.DstPort,
		"transport": pkt.Proto,
	}

	// Check for RDP Negotiation Response after X.224 fixed header.
	dataStart := 11
	if dataStart+8 <= tpktLen && tpktLen <= len(p) {
		data := p[dataStart:tpktLen]
		if len(data) >= 8 && data[0] == rdpNegResp {
			// flags(1) + length(2) + selectedProtocol(4)
			negLen := binary.LittleEndian.Uint16(data[2:4])
			if negLen == 8 {
				selProto := binary.LittleEndian.Uint32(data[4:8])
				selName, secLevel := decodeSelectedProtocol(selProto)
				attrs["selected_protocol"] = selName
				attrs["security_level"] = secLevel
				attrs["stage"] = "negotiation"

				if selProto == rdpProtoStandard {
					attrs["security_concern"] = "standard RDP security offers weak encryption and is vulnerable to MITM attacks"
				}

				ev := dpi.Event{
					FlowID:     state.Key.Hash(),
					Proto:      "rdp",
					Kind:       "negotiation",
					Attributes: attrs,
					Timestamp:  time.Now().UTC(),
				}
				return []dpi.Event{ev}, nil
			}
		}
	}

	ev := dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "rdp",
		Kind:       "connection_confirm",
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
	return []dpi.Event{ev}, nil
}

// parseMCSConnectInitial emits an event when MCS Connect Initial is detected.
func (d *RDPDecoder) parseMCSConnectInitial(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	attrs := map[string]any{
		"stage":     "mcs_connect",
		"src_port":  pkt.SrcPort,
		"dst_port":  pkt.DstPort,
		"transport": pkt.Proto,
	}
	ev := dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "rdp",
		Kind:       "mcs_connect",
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
	return []dpi.Event{ev}, nil
}

// extractCookie looks for "Cookie: mstshash=<value>\r\n" in the X.224 data portion.
func extractCookie(data []byte) string {
	idx := bytes.Index(data, cookiePrefix)
	if idx < 0 {
		return ""
	}
	start := idx + len(cookiePrefix)
	if start >= len(data) {
		return ""
	}

	// Find end of cookie (CR LF).
	limit := len(data)
	if limit > start+maxCookieLen {
		limit = start + maxCookieLen
	}
	end := -1
	for i := start; i < limit; i++ {
		if data[i] == '\r' || data[i] == '\n' {
			end = i
			break
		}
	}
	if end < 0 {
		// No terminator found; take what we have up to limit.
		end = limit
	}
	if end <= start {
		return ""
	}
	return string(data[start:end])
}

// findNegReq locates an RDP Negotiation Request structure in the data.
// It looks for type byte 0x01 followed by flags 0x00 and length 0x0008.
func findNegReq(data []byte) int {
	// The negotiation request is typically at the end of the CR data,
	// after the cookie (if any). Scan for the signature.
	for i := 0; i+8 <= len(data); i++ {
		if data[i] == rdpNegReq && data[i+1] == 0x00 {
			negLen := binary.LittleEndian.Uint16(data[i+2 : i+4])
			if negLen == 8 {
				return i
			}
		}
	}
	return -1
}

// decodeRequestedProtocols interprets the requestedProtocols bitmask and
// returns a list of protocol names and the highest security level.
func decodeRequestedProtocols(flags uint32) ([]string, string) {
	if flags == 0 {
		return []string{"standard_rdp"}, "standard_rdp"
	}

	var protos []string
	secLevel := "standard_rdp"

	if flags&rdpProtoTLS != 0 {
		protos = append(protos, "tls")
		secLevel = "tls"
	}
	if flags&rdpProtoCredSSP != 0 {
		protos = append(protos, "nla")
		secLevel = "nla"
	}
	if flags&rdpProtoRDSTLS != 0 {
		protos = append(protos, "rdstls")
	}
	if flags&rdpProtoCredSSPEarly != 0 {
		protos = append(protos, "nla_early_auth")
		secLevel = "nla_early_auth"
	}

	if len(protos) == 0 {
		return []string{"standard_rdp"}, "standard_rdp"
	}
	return protos, secLevel
}

// decodeSelectedProtocol maps a selectedProtocol value to name and security level.
func decodeSelectedProtocol(proto uint32) (string, string) {
	switch proto {
	case rdpProtoStandard:
		return "standard_rdp", "standard_rdp"
	case rdpProtoTLS:
		return "tls", "tls"
	case rdpProtoCredSSP:
		return "nla", "nla"
	case rdpProtoRDSTLS:
		return "rdstls", "rdstls"
	case rdpProtoCredSSPEarly:
		return "nla_early_auth", "nla_early_auth"
	default:
		return "unknown", "unknown"
	}
}
