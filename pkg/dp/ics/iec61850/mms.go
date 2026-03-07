// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package iec61850

import (
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// TPKT header constants.
const (
	tpktVersion = 0x03
	tpktHdrLen  = 4
)

// COTP PDU types.
const (
	cotpDT = 0xF0 // Data Transfer
	cotpCR = 0xE0 // Connection Request
	cotpCC = 0xD0 // Connection Confirm
)

// s7commProtocolID is the protocol ID byte that identifies S7comm payloads
// inside a COTP DT frame. If this byte appears after COTP, the packet
// belongs to S7comm and not MMS.
const s7commProtocolID = 0x32

// MMS ASN.1 context-class tags for confirmed-request service choices.
// These are the outer tag bytes seen in the PDU.
const (
	mmsTagGetNameList              = 0xA1
	mmsTagRead                     = 0xA4
	mmsTagWrite                    = 0xA5
	mmsTagGetVariableAccessAttrs   = 0xA6
	mmsTagDefineNamedVariableList  = 0xAB
	mmsTagGetNamedVarListAttrs     = 0xAC
	mmsTagDeleteNamedVariableList  = 0xAD
	mmsTagObtainFile               = 0xAE
)

// MMS PDU type tags (outermost ASN.1 tag).
const (
	mmsPDUConfirmedRequest  = 0xA0
	mmsPDUConfirmedResponse = 0xA1
	mmsPDUUnconfirmedPDU    = 0xA3
	mmsPDUInitiateRequest   = 0xA8
	mmsPDUInitiateResponse  = 0xA9
)

// mmsServiceName maps context tags inside a confirmed-request/response to
// human-readable service names.
var mmsServiceName = map[byte]string{
	mmsTagGetNameList:              "get_name_list",
	mmsTagRead:                     "read",
	mmsTagWrite:                    "write",
	mmsTagGetVariableAccessAttrs:   "get_variable_access_attributes",
	mmsTagDefineNamedVariableList:  "define_named_variable_list",
	mmsTagGetNamedVarListAttrs:     "get_named_variable_list_attributes",
	mmsTagDeleteNamedVariableList:  "delete_named_variable_list",
	mmsTagObtainFile:               "obtain_file",
}

// mmsWriteServices are service tags that perform write/control operations.
var mmsWriteServices = map[byte]bool{
	mmsTagWrite:                    true,
	mmsTagDefineNamedVariableList:  true,
	mmsTagDeleteNamedVariableList:  true,
}

// mmsControlServices are service tags that perform control operations.
var mmsControlServices = map[byte]bool{
	mmsTagWrite:                    true,
	mmsTagDefineNamedVariableList:  true,
	mmsTagDeleteNamedVariableList:  true,
	mmsTagObtainFile:               true,
}

// MMSDecoder implements dpi.Decoder for IEC 61850 MMS visibility.
// MMS runs over the ISO/ACSE stack on TCP port 102 (same as S7comm).
// The decoder differentiates from S7comm by inspecting the byte after the
// COTP header: S7comm starts with 0x32, while MMS uses ASN.1/BER tags.
type MMSDecoder struct{}

// NewMMSDecoder returns a new MMS protocol decoder.
func NewMMSDecoder() *MMSDecoder { return &MMSDecoder{} }

// Ports implements dpi.PortHinter for port-based dispatch.
func (d *MMSDecoder) Ports() (tcpPorts, udpPorts []uint16) {
	return []uint16{102}, nil
}

// Supports returns true for TCP flows on port 102 (shared with S7comm).
func (d *MMSDecoder) Supports(state *flow.State) bool {
	if state == nil {
		return false
	}
	if state.Key.Proto != 6 { // TCP only
		return false
	}
	return state.Key.SrcPort == 102 || state.Key.DstPort == 102
}

// OnPacket parses TPKT+COTP, differentiates MMS from S7comm, and extracts
// the MMS service type.
func (d *MMSDecoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil || len(pkt.Payload) == 0 {
		return nil, nil
	}

	payload := pkt.Payload

	// --- TPKT header (4 bytes) ---
	if len(payload) < tpktHdrLen {
		return nil, nil
	}
	if payload[0] != tpktVersion {
		return nil, nil
	}
	// TPKT length is bytes 2-3 (big-endian).
	tpktLen := int(payload[2])<<8 | int(payload[3])
	if tpktLen < tpktHdrLen || tpktLen > len(payload) {
		return nil, nil
	}

	// --- COTP header ---
	cotpStart := tpktHdrLen
	if len(payload) <= cotpStart {
		return nil, nil
	}
	cotpLen := int(payload[cotpStart]) // length indicator (excludes itself)
	if cotpLen < 1 || cotpStart+1+cotpLen > len(payload) {
		return nil, nil
	}
	cotpPDUType := payload[cotpStart+1] & 0xF0

	// For non-DT PDUs (CR/CC), just note connection setup.
	if cotpPDUType == cotpCR || cotpPDUType == cotpCC {
		kind := "connection_request"
		if cotpPDUType == cotpCC {
			kind = "connection_confirm"
		}
		attrs := map[string]any{
			"service": "connection",
		}
		ev := dpi.Event{
			FlowID:     state.Key.Hash(),
			Proto:      "mms",
			Kind:       kind,
			Attributes: attrs,
			Timestamp:  time.Now().UTC(),
		}
		return []dpi.Event{ev}, nil
	}

	// Only handle COTP DT (Data Transfer).
	if cotpPDUType != cotpDT {
		return nil, nil
	}

	// The MMS/S7comm payload starts after the COTP header.
	mmsStart := cotpStart + 1 + cotpLen
	if mmsStart >= len(payload) {
		return nil, nil
	}

	// --- Differentiate S7comm vs MMS ---
	// S7comm payloads start with protocol ID 0x32.
	if payload[mmsStart] == s7commProtocolID {
		// This is S7comm traffic — let the S7comm decoder handle it.
		return nil, nil
	}

	// --- MMS payload (ASN.1/BER encoded) ---
	mmsPayload := payload[mmsStart:]

	// The outermost tag identifies the MMS PDU type.
	if len(mmsPayload) < 2 {
		return nil, nil
	}

	pduTag := mmsPayload[0]
	kind := mmsPDUKind(pduTag)

	// Skip the outer tag + length to find the service tag inside.
	inner, ok := skipASN1TagLength(mmsPayload)
	if !ok || len(inner) == 0 {
		// Emit a generic MMS event even if we can't parse the inner content.
		attrs := map[string]any{
			"pdu_tag": fmt.Sprintf("0x%02X", pduTag),
		}
		addRawHex(attrs, pkt.Payload)
		ev := dpi.Event{
			FlowID:     state.Key.Hash(),
			Proto:      "mms",
			Kind:       kind,
			Attributes: attrs,
			Timestamp:  time.Now().UTC(),
		}
		return []dpi.Event{ev}, nil
	}

	// For confirmed request/response, skip the invoke-id to find the
	// service choice tag.
	serviceTag, serviceName := extractServiceTag(pduTag, inner)

	isWrite := mmsWriteServices[serviceTag]
	isControl := mmsControlServices[serviceTag]

	attrs := map[string]any{
		"service":    serviceName,
		"pdu_tag":    fmt.Sprintf("0x%02X", pduTag),
		"is_write":   isWrite,
		"is_control": isControl,
	}
	if serviceTag != 0 {
		attrs["service_tag"] = fmt.Sprintf("0x%02X", serviceTag)
	}
	addRawHex(attrs, pkt.Payload)

	ev := dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "mms",
		Kind:       kind,
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
	return []dpi.Event{ev}, nil
}

// OnFlowEnd is a no-op for MMS.
func (d *MMSDecoder) OnFlowEnd(state *flow.State) ([]dpi.Event, error) {
	return nil, nil
}

// mmsPDUKind returns the event kind string for an MMS PDU tag.
func mmsPDUKind(tag byte) string {
	switch tag {
	case mmsPDUConfirmedRequest:
		return "request"
	case mmsPDUConfirmedResponse:
		return "response"
	case mmsPDUUnconfirmedPDU:
		return "unconfirmed"
	case mmsPDUInitiateRequest:
		return "initiate_request"
	case mmsPDUInitiateResponse:
		return "initiate_response"
	default:
		return "unknown"
	}
}

// extractServiceTag tries to find the MMS service choice tag inside the
// confirmed request/response PDU content. For confirmed requests, the
// structure is: invoke-id (integer), then the service choice (context tag).
// We do a simplified scan: skip TLV elements until we find a context-class
// constructed tag (0xA0-0xBF range).
func extractServiceTag(pduTag byte, inner []byte) (byte, string) {
	if pduTag != mmsPDUConfirmedRequest && pduTag != mmsPDUConfirmedResponse {
		return 0, mmsPDUKind(pduTag)
	}

	// Walk through TLV elements looking for a context-class constructed tag.
	pos := 0
	for pos < len(inner) {
		tag := inner[pos]
		// Context-class constructed tags are 0xA0-0xBF.
		if tag >= 0xA0 && tag <= 0xBF {
			if name, ok := mmsServiceName[tag]; ok {
				return tag, name
			}
			return tag, fmt.Sprintf("unknown_service_0x%02X", tag)
		}
		// Skip this entire TLV element.
		totalLen := asn1ElementSize(inner[pos:])
		if totalLen <= 0 {
			break
		}
		pos += totalLen
	}
	return 0, "unknown_service"
}

// skipASN1TagLength skips the tag and length bytes of a BER-TLV element,
// returning the value portion. Returns ok=false if the data is malformed.
func skipASN1TagLength(data []byte) ([]byte, bool) {
	if len(data) < 2 {
		return nil, false
	}
	pos := 1
	// Handle multi-byte tags (tag number >= 31).
	if data[0]&0x1F == 0x1F {
		for pos < len(data) && data[pos]&0x80 != 0 {
			pos++
		}
		pos++ // skip last tag byte
		if pos >= len(data) {
			return nil, false
		}
	}
	// Parse length.
	if data[pos]&0x80 == 0 {
		// Short form.
		l := int(data[pos])
		pos++
		if pos+l > len(data) {
			return data[pos:], true
		}
		return data[pos : pos+l], true
	}
	// Long form.
	numBytes := int(data[pos] & 0x7F)
	pos++
	if numBytes == 0 || numBytes > 4 || pos+numBytes > len(data) {
		return nil, false
	}
	l := 0
	for i := 0; i < numBytes; i++ {
		l = l<<8 | int(data[pos])
		pos++
	}
	if pos+l > len(data) {
		return data[pos:], true
	}
	return data[pos : pos+l], true
}

// asn1ValueLength returns the value length encoded in a BER-TLV element.
// Returns -1 if the encoding is malformed.
func asn1ValueLength(data []byte) int {
	if len(data) < 2 {
		return -1
	}
	pos := 1
	if data[0]&0x1F == 0x1F {
		for pos < len(data) && data[pos]&0x80 != 0 {
			pos++
		}
		pos++
		if pos >= len(data) {
			return -1
		}
	}
	if data[pos]&0x80 == 0 {
		return int(data[pos])
	}
	numBytes := int(data[pos] & 0x7F)
	pos++
	if numBytes == 0 || numBytes > 4 || pos+numBytes > len(data) {
		return -1
	}
	l := 0
	for i := 0; i < numBytes; i++ {
		l = l<<8 | int(data[pos])
		pos++
	}
	return l
}

// asn1ElementSize returns the total size (tag + length + value) of a
// BER-TLV element. Returns -1 if the encoding is malformed.
func asn1ElementSize(data []byte) int {
	if len(data) < 2 {
		return -1
	}
	pos := 1
	// Multi-byte tag.
	if data[0]&0x1F == 0x1F {
		for pos < len(data) && data[pos]&0x80 != 0 {
			pos++
		}
		pos++
		if pos >= len(data) {
			return -1
		}
	}
	// Parse length.
	if data[pos]&0x80 == 0 {
		return pos + 1 + int(data[pos])
	}
	numBytes := int(data[pos] & 0x7F)
	pos++
	if numBytes == 0 || numBytes > 4 || pos+numBytes > len(data) {
		return -1
	}
	l := 0
	for i := 0; i < numBytes; i++ {
		l = l<<8 | int(data[pos])
		pos++
	}
	return pos + l
}

// addRawHex appends a capped hex representation of the payload.
func addRawHex(attrs map[string]any, raw []byte) {
	if len(raw) > 512 {
		raw = raw[:512]
	}
	attrs["raw_hex"] = hex.EncodeToString(raw)
}

// Helper for tests/mocks.
func mmsKeyFor(src, dst string, sport, dport uint16) flow.Key {
	return flow.Key{
		SrcIP:   net.ParseIP(src),
		DstIP:   net.ParseIP(dst),
		SrcPort: sport,
		DstPort: dport,
		Proto:   6,
		Dir:     flow.DirForward,
	}
}
