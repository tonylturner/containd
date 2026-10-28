// SPDX-License-Identifier: Apache-2.0
package cip

import "encoding/binary"

// One budget covers the entire tree, not each nested envelope. The root
// message is outside the child budget. Depth is bounded separately for stack use.
const (
	maxMSPServices = 32
	maxMSPDepth    = 8
)

type MSPChild struct {
	*CIPMessage
	Index  uint16
	Offset uint16
	Nested *MSPResult
}

// MSPResult separates wire violations from content not inspected. Children
// retain their own request/response headers and original table positions.
type MSPResult struct {
	Declared    uint16
	Children    []MSPChild
	Conformance []string
	Undecoded   []string
}

func ParseMSPServices(data []byte) MSPResult {
	budget := maxMSPServices
	return parseMSP(data, nil, &budget, 0)
}

func hasMSPBody(msg *CIPMessage) bool {
	return msg.ServiceCode == 0x0a && (!msg.IsResponse ||
		msg.Response != nil && msg.Response.GeneralStatus != nil &&
			(*msg.Response.GeneralStatus == 0 || *msg.Response.GeneralStatus == 0x1e))
}

func parseMSP(data []byte, response *bool, budget *int, depth int) MSPResult {
	var r MSPResult
	if len(data) >= 2 {
		r.Declared = binary.LittleEndian.Uint16(data)
	}
	if depth >= maxMSPDepth {
		r.Undecoded = []string{"cip.msp_nesting"}
		return r
	}
	if len(data) < 2 {
		r.Conformance = []string{"cip.msp_layout"}
		return r
	}
	tableEnd := 2 + int(r.Declared)*2
	if tableEnd > len(data) {
		r.Conformance = []string{"cip.msp_layout"}
		return r
	}
	highWater := tableEnd
	if r.Declared == 0 && len(data) != tableEnd {
		r.Conformance = append(r.Conformance, "cip.msp_layout")
	}
	for i := 0; i < int(r.Declared); i++ {
		off := int(binary.LittleEndian.Uint16(data[2+2*i:]))
		end := len(data)
		if i+1 < int(r.Declared) {
			end = int(binary.LittleEndian.Uint16(data[4+2*i:]))
		}
		if off < highWater || end <= off || end > len(data) {
			r.Conformance = append(r.Conformance, "cip.msp_layout")
			// Never re-read a previously consumed or ambiguous interval.
			highWater = max(highWater, off)
			continue
		}
		if off != highWater {
			r.Conformance = append(r.Conformance, "cip.msp_layout")
		}
		highWater = end
		if *budget == 0 {
			r.Undecoded = append(r.Undecoded, "cip.msp_limit")
			break
		}
		*budget--
		msg, err := parseCIPFromItem(data[off:end])
		if msg == nil {
			r.Conformance = append(r.Conformance, "cip.message_short")
			continue
		}
		if err != nil {
			msg.Conformance = append(msg.Conformance, messageErrorCode(err))
		}
		if response != nil && msg.IsResponse != *response {
			msg.Conformance = append(msg.Conformance, "cip.msp_response_mismatch")
		}
		child := MSPChild{CIPMessage: msg, Index: uint16(i), Offset: uint16(off)}
		if hasMSPBody(msg) && err == nil {
			nested := parseMSP(msg.Data, &msg.IsResponse, budget, depth+1)
			child.Nested = &nested
		}
		r.Children = append(r.Children, child)
	}
	return r
}
