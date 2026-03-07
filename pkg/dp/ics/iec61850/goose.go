// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package iec61850

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// GOOSE Ethertype.
const gooseEthertype = 0x88B8

// GOOSEHeader represents the fixed header fields of a GOOSE frame.
type GOOSEHeader struct {
	APPID    uint16
	Length   uint16
	Reserved [4]byte
}

// GOOSEFields holds decoded fields from the GOOSE ASN.1 PDU.
type GOOSEFields struct {
	GoCBRef string
	GoID    string
	DatSet  string
	StNum   uint32
	SqNum   uint32
}

// GOOSEDecoder implements dpi.Decoder for IEC 61850 GOOSE visibility.
// GOOSE is a Layer 2 multicast protocol (Ethertype 0x88B8) and does not
// use TCP/IP. This decoder is largely a placeholder: Supports() returns
// false because our capture pipeline currently works at the IP layer.
// When raw Ethernet capture support is added, Supports() can be updated
// to activate GOOSE decoding.
type GOOSEDecoder struct{}

// NewGOOSEDecoder returns a new GOOSE protocol decoder.
func NewGOOSEDecoder() *GOOSEDecoder { return &GOOSEDecoder{} }

// Supports always returns false because GOOSE is a Layer 2 protocol and
// requires raw Ethernet capture which is not yet available.
func (d *GOOSEDecoder) Supports(_ *flow.State) bool {
	return false
}

// OnPacket parses a GOOSE frame if one is ever presented to the decoder.
// In the current architecture this will not be called (Supports returns
// false), but the parsing logic is implemented for when raw Ethernet
// capture is added.
func (d *GOOSEDecoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil || len(pkt.Payload) == 0 {
		return nil, nil
	}

	hdr, fields, err := ParseGOOSE(pkt.Payload)
	if err != nil {
		return nil, nil
	}

	attrs := map[string]any{
		"appid": fmt.Sprintf("0x%04X", hdr.APPID),
	}
	if fields != nil {
		if fields.GoCBRef != "" {
			attrs["gocb_ref"] = fields.GoCBRef
		}
		if fields.GoID != "" {
			attrs["go_id"] = fields.GoID
		}
		if fields.DatSet != "" {
			attrs["dat_set"] = fields.DatSet
		}
		attrs["st_num"] = fields.StNum
		attrs["sq_num"] = fields.SqNum
	}

	// Include raw hex for operator visibility (cap to avoid huge payloads).
	raw := pkt.Payload
	if len(raw) > 512 {
		raw = raw[:512]
	}
	attrs["raw_hex"] = hex.EncodeToString(raw)

	flowID := ""
	if state != nil {
		flowID = state.Key.Hash()
	}
	ev := dpi.Event{
		FlowID:     flowID,
		Proto:      "goose",
		Kind:       "publish",
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
	return []dpi.Event{ev}, nil
}

// OnFlowEnd is a no-op for GOOSE.
func (d *GOOSEDecoder) OnFlowEnd(_ *flow.State) ([]dpi.Event, error) {
	return nil, nil
}

// ParseGOOSE parses a GOOSE frame from raw bytes (starting after the
// Ethernet header, i.e. the payload begins at the GOOSE APPID field).
// Returns the fixed header and best-effort parsed ASN.1 fields.
func ParseGOOSE(data []byte) (*GOOSEHeader, *GOOSEFields, error) {
	// Minimum: APPID(2) + Length(2) + Reserved(4) = 8 bytes.
	if len(data) < 8 {
		return nil, nil, fmt.Errorf("goose frame too short: %d bytes", len(data))
	}

	hdr := &GOOSEHeader{
		APPID:  binary.BigEndian.Uint16(data[0:2]),
		Length: binary.BigEndian.Uint16(data[2:4]),
	}
	copy(hdr.Reserved[:], data[4:8])

	// The ASN.1 BER-encoded PDU starts at offset 8.
	if len(data) <= 8 {
		return hdr, nil, nil
	}

	fields := parseGOOSEPDU(data[8:])
	return hdr, fields, nil
}

// GOOSE PDU ASN.1 context tags (IEC 61850-8-1).
const (
	gooseTagGoCBRef           = 0x80
	gooseTagTimeAllowedToLive = 0x81
	gooseTagDatSet            = 0x82
	gooseTagGoID              = 0x83
	gooseTagT                 = 0x84
	gooseTagStNum             = 0x85
	gooseTagSqNum             = 0x86
	gooseTagSimulation        = 0x87
	gooseTagConfRev           = 0x88
	gooseTagNdsCom            = 0x89
	gooseTagNumDatSetEntries  = 0x8A
	gooseTagAllData           = 0xAB
)

// parseGOOSEPDU does a best-effort parse of the GOOSE ASN.1 BER PDU.
func parseGOOSEPDU(data []byte) *GOOSEFields {
	// The outer element is typically a SEQUENCE (0x61 for goosePdu).
	if len(data) < 2 {
		return nil
	}
	// Skip the outer tag + length.
	inner, ok := skipASN1TagLength(data)
	if !ok || len(inner) == 0 {
		return nil
	}

	fields := &GOOSEFields{}
	pos := 0
	for pos < len(inner) {
		tag := inner[pos]
		elemSize := asn1ElementSize(inner[pos:])
		if elemSize <= 0 {
			break
		}
		val, valOK := skipASN1TagLength(inner[pos:])
		if !valOK {
			break
		}
		valLen := asn1ValueLength(inner[pos:])
		if valLen < 0 {
			valLen = len(val)
		}

		switch tag {
		case gooseTagGoCBRef:
			fields.GoCBRef = string(val[:minInt(valLen, len(val))])
		case gooseTagDatSet:
			fields.DatSet = string(val[:minInt(valLen, len(val))])
		case gooseTagGoID:
			fields.GoID = string(val[:minInt(valLen, len(val))])
		case gooseTagStNum:
			fields.StNum = decodeUint32(val[:minInt(valLen, len(val))])
		case gooseTagSqNum:
			fields.SqNum = decodeUint32(val[:minInt(valLen, len(val))])
		}

		pos += elemSize
	}
	return fields
}

// decodeUint32 decodes up to 4 bytes as a big-endian unsigned integer.
func decodeUint32(data []byte) uint32 {
	var v uint32
	for _, b := range data {
		v = v<<8 | uint32(b)
	}
	return v
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
