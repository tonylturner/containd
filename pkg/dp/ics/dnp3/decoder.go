// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dnp3

import (
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// Decoder implements dpi.Decoder for DNP3 visibility.
type Decoder struct{}

func NewDecoder() *Decoder { return &Decoder{} }

func (d *Decoder) Supports(state *flow.State) bool {
	if state == nil {
		return false
	}
	// Proto 6 is TCP.
	if state.Key.Proto != 6 {
		return false
	}
	return state.Key.SrcPort == 20000 || state.Key.DstPort == 20000
}

// Ports implements dpi.PortHinter for port-based dispatch.
func (d *Decoder) Ports() (tcpPorts, udpPorts []uint16) {
	return []uint16{20000}, nil
}

func (d *Decoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil || len(pkt.Payload) == 0 {
		return nil, nil
	}
	frame, err := ParseFrame(pkt.Payload)
	if err != nil {
		return nil, nil
	}

	fc := frame.FunctionCode
	isWrite := IsWriteFunctionCode(fc)
	isControl := IsControlFunctionCode(fc)

	kind := "request"
	if IsResponse(fc) {
		kind = "response"
	}
	// Classify dangerous function codes.
	if IsRestartFunctionCode(fc) {
		kind = "restart"
	} else if fc == FuncStopApplication || fc == FuncSaveConfiguration {
		kind = "control"
	}

	attrs := map[string]any{
		"function_code":       fc,
		"function_name":       FunctionCodeName(fc),
		"is_write":            isWrite,
		"is_control":          isControl,
		"source_address":      frame.Source,
		"destination_address": frame.Destination,
	}

	// Extract IIN flags from response messages.
	if iin1, iin2, ok := frame.IIN(); ok {
		flags := FormatIINFlags(iin1, iin2)
		if flags != "" {
			attrs["iin_flags"] = flags
		}
	}

	// Parse all object group headers.
	objOffset := 3 // Transport + AppControl + FuncCode
	if IsResponse(fc) {
		objOffset = 5 // +2 IIN bytes
	}
	objHeaders := ParseObjectHeaders(frame.Data, objOffset)
	if len(objHeaders) > 0 {
		// Emit comma-separated object groups.
		var b strings.Builder
		for i, oh := range objHeaders {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(strconv.FormatUint(uint64(oh.Group), 10))
		}
		attrs["object_groups"] = b.String()

		// Emit first header's qualifier and count for primary inspection.
		attrs["qualifier"] = objHeaders[0].Qualifier
		attrs["object_count"] = objHeaders[0].Count
	}

	// Include raw hex for operator visibility (cap to avoid huge payloads).
	raw := pkt.Payload
	if len(raw) > 512 {
		raw = raw[:512]
	}
	attrs["raw_hex"] = hex.EncodeToString(raw)

	ev := dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "dnp3",
		Kind:       kind,
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
	return []dpi.Event{ev}, nil
}

func (d *Decoder) OnFlowEnd(state *flow.State) ([]dpi.Event, error) {
	return nil, nil
}

// Helper for tests/mocks.
func keyFor(src, dst string, sport, dport uint16) flow.Key {
	return flow.Key{
		SrcIP:   net.ParseIP(src),
		DstIP:   net.ParseIP(dst),
		SrcPort: sport,
		DstPort: dport,
		Proto:   6,
		Dir:     flow.DirForward,
	}
}
