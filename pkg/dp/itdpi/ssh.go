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

// SSHDecoder parses SSH protocol version exchange and Key Exchange Init messages.
type SSHDecoder struct{}

func NewSSHDecoder() *SSHDecoder { return &SSHDecoder{} }

// Ports implements dpi.PortHinter for port-based dispatch.
func (d *SSHDecoder) Ports() (tcpPorts, udpPorts []uint16) {
	return []uint16{22, 2222, 8022}, nil
}

func (d *SSHDecoder) Supports(state *flow.State) bool {
	if state == nil || state.Key.Proto != 6 {
		return false
	}
	switch state.Key.SrcPort {
	case 22, 2222, 8022:
		return true
	}
	switch state.Key.DstPort {
	case 22, 2222, 8022:
		return true
	}
	return false
}

func (d *SSHDecoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil || len(pkt.Payload) == 0 {
		return nil, nil
	}

	// Try SSH version exchange first (lines starting with "SSH-").
	if ev, ok := d.parseVersionExchange(state, pkt); ok {
		return []dpi.Event{ev}, nil
	}

	// Try SSH binary packet: check for KEX_INIT (message type 20).
	if ev, ok := d.parseKexInit(state, pkt); ok {
		return []dpi.Event{ev}, nil
	}

	return nil, nil
}

func (d *SSHDecoder) OnFlowEnd(state *flow.State) ([]dpi.Event, error) { return nil, nil }

// parseVersionExchange detects "SSH-" protocol version exchange lines.
// Format: SSH-protoversion-softwareversion SP comments CR LF
func (d *SSHDecoder) parseVersionExchange(state *flow.State, pkt *dpi.ParsedPacket) (dpi.Event, bool) {
	p := pkt.Payload
	if len(p) < 4 || !bytes.HasPrefix(p, []byte("SSH-")) {
		return dpi.Event{}, false
	}

	// Find the end of line (CR LF or LF). Limit scan to prevent
	// unbounded reads on large payloads.
	limit := len(p)
	if limit > 256 {
		limit = 256
	}

	lineEnd := -1
	for i := 4; i < limit; i++ {
		if p[i] == '\n' {
			lineEnd = i
			break
		}
	}
	if lineEnd < 0 {
		// No newline found in first 256 bytes — not a valid version string.
		return dpi.Event{}, false
	}

	line := p[4:lineEnd]
	// Strip trailing CR if present.
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}

	// Parse: protoversion-softwareversion[ SP comments]
	version := ""
	software := ""
	comments := ""

	dashIdx := bytes.IndexByte(line, '-')
	if dashIdx < 0 {
		// Malformed, but still emit what we can.
		version = string(line)
	} else {
		version = string(line[:dashIdx])
		rest := line[dashIdx+1:]
		spIdx := bytes.IndexByte(rest, ' ')
		if spIdx >= 0 {
			software = string(rest[:spIdx])
			comments = string(rest[spIdx+1:])
		} else {
			software = string(rest)
		}
	}

	attrs := map[string]any{
		"version":   version,
		"software":  software,
		"src_port":  pkt.SrcPort,
		"dst_port":  pkt.DstPort,
		"transport": pkt.Proto,
	}
	if comments != "" {
		attrs["comments"] = comments
	}

	ev := dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "ssh",
		Kind:       "version_exchange",
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
	return ev, true
}

// parseKexInit looks for SSH binary packets with message type 20 (SSH_MSG_KEXINIT).
// SSH binary packet format:
//
//	uint32  packet_length
//	byte    padding_length
//	byte[]  payload (first byte = message type)
//	byte[]  padding
//
// KEX_INIT payload after type byte:
//
//	byte[16] cookie
//	name-list kex_algorithms
//	name-list server_host_key_algorithms
//	name-list encryption_algorithms_client_to_server
//	...
func (d *SSHDecoder) parseKexInit(state *flow.State, pkt *dpi.ParsedPacket) (dpi.Event, bool) {
	p := pkt.Payload
	// Minimum: 4 (packet_length) + 1 (padding_length) + 1 (msg type) + 16 (cookie) = 22
	if len(p) < 22 {
		return dpi.Event{}, false
	}

	pktLen := binary.BigEndian.Uint32(p[0:4])
	// Sanity: packet_length should be reasonable and not exceed payload.
	if pktLen < 2 || pktLen > 65536 {
		return dpi.Event{}, false
	}

	paddingLen := p[4]
	msgType := p[5]

	if msgType != 20 { // SSH_MSG_KEXINIT
		return dpi.Event{}, false
	}

	// Verify we have enough data for the payload portion.
	payloadEnd := int(pktLen) + 4 // packet_length field itself is not included in pktLen
	if payloadEnd > len(p) {
		payloadEnd = len(p)
	}
	payloadStart := 6 // after packet_length(4) + padding_length(1) + msg_type(1)
	msgPayload := p[payloadStart:payloadEnd]

	// Subtract padding from usable payload.
	usable := len(msgPayload) - int(paddingLen)
	if usable < 16 {
		return dpi.Event{}, false
	}
	msgPayload = msgPayload[:usable]

	// Skip 16-byte cookie.
	off := 16

	// Parse name-lists: kex_algorithms, server_host_key_algorithms,
	// encryption_algorithms_client_to_server.
	kexAlg := ""
	encAlg := ""

	for i := 0; i < 3; i++ {
		name, next, ok := parseNameList(msgPayload, off)
		if !ok {
			break
		}
		switch i {
		case 0: // kex_algorithms — take first entry
			kexAlg = firstEntry(name)
		case 2: // encryption_algorithms_client_to_server — take first entry
			encAlg = firstEntry(name)
		}
		off = next
	}

	if kexAlg == "" && encAlg == "" {
		return dpi.Event{}, false
	}

	attrs := map[string]any{
		"kex_algorithm": kexAlg,
		"encryption":    encAlg,
		"src_port":      pkt.SrcPort,
		"dst_port":      pkt.DstPort,
		"transport":     pkt.Proto,
	}

	ev := dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "ssh",
		Kind:       "kex_init",
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
	return ev, true
}

// parseNameList reads an SSH name-list (uint32 length + comma-separated string)
// and returns the raw string, the offset past this name-list, and success.
func parseNameList(buf []byte, off int) (string, int, bool) {
	if off+4 > len(buf) {
		return "", off, false
	}
	nameLen := int(binary.BigEndian.Uint32(buf[off : off+4]))
	off += 4
	if nameLen < 0 || off+nameLen > len(buf) {
		return "", off, false
	}
	// Cap to avoid large allocations on malformed data.
	if nameLen > 4096 {
		nameLen = 4096
	}
	s := string(buf[off : off+nameLen])
	return s, off + nameLen, true
}

// firstEntry returns the first comma-separated entry from an SSH name-list string.
func firstEntry(nameList string) string {
	for i := 0; i < len(nameList); i++ {
		if nameList[i] == ',' {
			return nameList[:i]
		}
	}
	return nameList
}
