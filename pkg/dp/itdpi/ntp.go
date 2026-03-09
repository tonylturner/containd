// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package itdpi

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// ntpMinLen is the minimum NTP packet size per RFC 5905.
const ntpMinLen = 48

// NTP mode constants.
const (
	ntpModeSymmetricActive  = 1
	ntpModeSymmetricPassive = 2
	ntpModeClient           = 3
	ntpModeServer           = 4
	ntpModeBroadcast        = 5
	ntpModeControl          = 6
	ntpModePrivate          = 7
)

// NTPDecoder parses NTP packets (RFC 5905) and emits protocol events.
type NTPDecoder struct{}

func NewNTPDecoder() *NTPDecoder { return &NTPDecoder{} }

// Ports implements dpi.PortHinter for port-based dispatch.
func (d *NTPDecoder) Ports() (tcpPorts, udpPorts []uint16) {
	return nil, []uint16{123}
}

func (d *NTPDecoder) Supports(state *flow.State) bool {
	if state == nil || state.Key.Proto != 17 {
		return false
	}
	return state.Key.SrcPort == 123 || state.Key.DstPort == 123
}

func (d *NTPDecoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil || len(pkt.Payload) < ntpMinLen {
		return nil, nil
	}
	p := pkt.Payload

	// Byte 0: LI (2 bits) | VN (3 bits) | Mode (3 bits)
	li := (p[0] >> 6) & 0x03
	vn := (p[0] >> 3) & 0x07
	mode := p[0] & 0x07

	// Sanity: NTP versions 1-4 are valid. Reject anything else as non-NTP.
	if vn < 1 || vn > 4 {
		return nil, nil
	}

	// Validate mode range.
	if mode == 0 || mode > ntpModePrivate {
		return nil, nil
	}

	stratum := p[1]
	poll := int8(p[2])
	precision := int8(p[3])

	// Root Delay and Root Dispersion as 32-bit fixed-point (seconds).
	rootDelay := ntpFixed32(binary.BigEndian.Uint32(p[4:8]))
	rootDispersion := ntpFixed32(binary.BigEndian.Uint32(p[8:12]))

	// Reference ID interpretation depends on stratum.
	refID := p[12:16]
	refIDStr := formatRefID(refID, stratum)

	// Determine event kind.
	kind := ntpEventKind(mode)

	attrs := map[string]any{
		"version":         vn,
		"mode":            mode,
		"mode_name":       ntpModeName(mode),
		"leap_indicator":  li,
		"stratum":         stratum,
		"stratum_name":    ntpStratumName(stratum),
		"poll":            math.Pow(2, float64(poll)),
		"precision":       precision,
		"root_delay":      rootDelay,
		"root_dispersion": rootDispersion,
		"reference_id":    refIDStr,
		"src_port":        pkt.SrcPort,
		"dst_port":        pkt.DstPort,
		"transport":       pkt.Proto,
	}

	// Flag potentially dangerous control/private modes (amplification risk).
	if mode == ntpModeControl || mode == ntpModePrivate {
		attrs["dangerous"] = true
		attrs["risk"] = "NTP control/monlist amplification"
	}

	_ = precision // already stored in attrs

	ev := dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "ntp",
		Kind:       kind,
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
	return []dpi.Event{ev}, nil
}

func (d *NTPDecoder) OnFlowEnd(state *flow.State) ([]dpi.Event, error) { return nil, nil }

// ntpFixed32 converts an NTP 32-bit fixed-point value (16.16) to float64 seconds.
func ntpFixed32(v uint32) float64 {
	return float64(v) / 65536.0
}

// formatRefID returns a human-readable reference ID.
// For stratum 1: 4-byte ASCII identifier (e.g., "GPS", "PPS").
// For stratum 2+: IPv4 address.
func formatRefID(id []byte, stratum uint8) string {
	if len(id) < 4 {
		return ""
	}
	if stratum <= 1 {
		// ASCII reference clock identifier; strip trailing NULs.
		end := 4
		for end > 0 && id[end-1] == 0 {
			end--
		}
		return string(id[:end])
	}
	// Stratum 2+: IPv4 address.
	return net.IPv4(id[0], id[1], id[2], id[3]).String()
}

// ntpModeName returns a human-readable name for the NTP mode.
func ntpModeName(mode uint8) string {
	switch mode {
	case ntpModeSymmetricActive:
		return "symmetric_active"
	case ntpModeSymmetricPassive:
		return "symmetric_passive"
	case ntpModeClient:
		return "client"
	case ntpModeServer:
		return "server"
	case ntpModeBroadcast:
		return "broadcast"
	case ntpModeControl:
		return "control"
	case ntpModePrivate:
		return "private"
	default:
		return fmt.Sprintf("unknown(%d)", mode)
	}
}

// ntpEventKind maps NTP mode to an event kind string.
func ntpEventKind(mode uint8) string {
	switch mode {
	case ntpModeClient:
		return "request"
	case ntpModeServer:
		return "response"
	case ntpModeBroadcast:
		return "broadcast"
	case ntpModeControl, ntpModePrivate:
		return "control"
	default:
		return "exchange"
	}
}

// ntpStratumName returns a description for the stratum value.
func ntpStratumName(s uint8) string {
	switch {
	case s == 0:
		return "unspecified"
	case s == 1:
		return "primary"
	case s >= 2 && s <= 15:
		return "secondary"
	case s == 16:
		return "unsynchronized"
	default:
		return "reserved"
	}
}
