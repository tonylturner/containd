// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package itdpi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// SMBDecoder parses SMBv1 and SMBv2/3 headers to emit negotiate, session setup,
// tree connect, read, write, and other command events.
const (
	maxSMBDialects       = 64
	maxSMBDialectBytes   = 4096
	maxSMBNegotiationMap = 4096
)

type smbNegotiation struct {
	dialects []string
	updated  time.Time
}

type SMBDecoder struct {
	mu           sync.Mutex
	negotiations map[string]smbNegotiation
}

func NewSMBDecoder() *SMBDecoder { return &SMBDecoder{} }

// Ports implements dpi.PortHinter for port-based dispatch.
func (d *SMBDecoder) Ports() (tcpPorts, udpPorts []uint16) {
	return []uint16{445, 139}, nil
}

func (d *SMBDecoder) Supports(state *flow.State) bool {
	if state == nil || state.Key.Proto != 6 {
		return false
	}
	switch state.Key.SrcPort {
	case 445, 139:
		return true
	}
	switch state.Key.DstPort {
	case 445, 139:
		return true
	}
	return false
}

// SMB magic bytes.
var (
	smbV1Magic = []byte{0xFF, 'S', 'M', 'B'}
	smbV2Magic = []byte{0xFE, 'S', 'M', 'B'}
)

// SMBv2 command names by command code.
var smbV2Commands = map[uint16]string{
	0x0000: "negotiate",
	0x0001: "session_setup",
	0x0002: "logoff",
	0x0003: "tree_connect",
	0x0004: "tree_disconnect",
	0x0005: "create",
	0x0006: "close",
	0x0007: "flush",
	0x0008: "read",
	0x0009: "write",
	0x000A: "lock",
	0x000B: "ioctl",
	0x000C: "cancel",
	0x000D: "echo",
	0x000E: "query_directory",
	0x000F: "change_notify",
	0x0010: "query_info",
	0x0011: "set_info",
}

func (d *SMBDecoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil || len(pkt.Payload) < 8 {
		return nil, nil
	}

	p := pkt.Payload

	// NetBIOS Session Service header: 1 byte type (0x00) + 3 bytes length.
	if p[0] != 0x00 {
		return nil, nil
	}
	nbLen := int(p[1])<<16 | int(p[2])<<8 | int(p[3])
	if nbLen < 4 || 4+nbLen > len(p) {
		// Truncated — use what we have.
		nbLen = len(p) - 4
		if nbLen < 4 {
			return nil, nil
		}
	}
	smb := p[4 : 4+nbLen]

	if len(smb) < 4 {
		return nil, nil
	}

	// Check magic bytes.
	if smb[0] == smbV1Magic[0] && smb[1] == smbV1Magic[1] && smb[2] == smbV1Magic[2] && smb[3] == smbV1Magic[3] {
		return d.parseSMBv1(state, pkt, smb)
	}
	if smb[0] == smbV2Magic[0] && smb[1] == smbV2Magic[1] && smb[2] == smbV2Magic[2] && smb[3] == smbV2Magic[3] {
		return d.parseSMBv2(state, pkt, smb)
	}

	return nil, nil
}

func (d *SMBDecoder) OnFlowEnd(state *flow.State) ([]dpi.Event, error) {
	if state != nil {
		d.mu.Lock()
		delete(d.negotiations, smbNegotiationKey(state.Key))
		d.mu.Unlock()
	}
	return nil, nil
}

func (d *SMBDecoder) parseSMBv1(state *flow.State, pkt *dpi.ParsedPacket, smb []byte) ([]dpi.Event, error) {
	// SMBv1 header is 32 bytes minimum.
	if len(smb) < 32 {
		return nil, nil
	}

	cmd := smb[4] // command byte at offset 4
	cmdName := smbV1CommandName(cmd)

	attrs := map[string]any{
		"version":   "SMB1",
		"command":   cmdName,
		"src_port":  pkt.SrcPort,
		"dst_port":  pkt.DstPort,
		"transport": pkt.Proto,
	}
	if cmd == 0x72 {
		if smb[9]&0x80 != 0 {
			if dialect, ok := d.selectedSMB1Dialect(state, smb); ok {
				attrs["dialect"] = dialect
			}
		} else if dialects, ok := parseSMB1Dialects(smb); ok {
			attrs["dialects_offered"] = dialects
			d.storeSMB1Dialects(state, dialects)
		}
	}

	ev := dpi.Event{
		FlowID:     state.ID(),
		Proto:      "smb",
		Kind:       cmdName,
		Attributes: attrs,
	}
	return []dpi.Event{ev}, nil
}

func (d *SMBDecoder) parseSMBv2(state *flow.State, pkt *dpi.ParsedPacket, smb []byte) ([]dpi.Event, error) {
	// SMBv2 header is 64 bytes.
	if len(smb) < 64 {
		return nil, nil
	}

	cmd := binary.LittleEndian.Uint16(smb[12:14])
	sessionID := binary.LittleEndian.Uint64(smb[44:52])

	cmdName, ok := smbV2Commands[cmd]
	if !ok {
		cmdName = "unknown"
	}

	attrs := map[string]any{
		"version":    "SMB2",
		"command":    cmdName,
		"session_id": sessionID,
		"src_port":   pkt.SrcPort,
		"dst_port":   pkt.DstPort,
		"transport":  pkt.Proto,
	}
	if cmd == 0x0000 {
		if binary.LittleEndian.Uint32(smb[16:20])&1 != 0 {
			if dialect, ok := parseSMB2SelectedDialect(smb); ok {
				attrs["dialect"] = dialect
			}
		} else if dialects, ok := parseSMB2Dialects(smb); ok {
			attrs["dialects_offered"] = dialects
		}
	}

	// For TreeConnect, try to extract the share name from the payload.
	if cmd == 0x0003 && len(smb) > 72 {
		if share := d.extractShareName(smb); share != "" {
			attrs["share"] = share
		}
	}

	ev := dpi.Event{
		FlowID:     state.ID(),
		Proto:      "smb",
		Kind:       cmdName,
		Attributes: attrs,
	}
	return []dpi.Event{ev}, nil
}

func parseSMB2Dialects(smb []byte) ([]string, bool) {
	if len(smb) < 100 || binary.LittleEndian.Uint16(smb[64:66]) != 36 {
		return nil, false
	}
	count := int(binary.LittleEndian.Uint16(smb[66:68]))
	if count == 0 || count > maxSMBDialects || count*2 > len(smb)-100 {
		return nil, false
	}
	dialects := make([]string, count)
	for i := range dialects {
		dialects[i] = smbDialectName(binary.LittleEndian.Uint16(smb[100+i*2 : 102+i*2]))
	}
	return dialects, true
}

func parseSMB2SelectedDialect(smb []byte) (string, bool) {
	if len(smb) < 70 || binary.LittleEndian.Uint16(smb[64:66]) != 65 {
		return "", false
	}
	return smbDialectName(binary.LittleEndian.Uint16(smb[68:70])), true
}

func smbDialectName(dialect uint16) string {
	switch dialect {
	case 0x0202:
		return "2.0.2"
	case 0x0210:
		return "2.1"
	case 0x02ff:
		return "2.??"
	case 0x0300:
		return "3.0"
	case 0x0302:
		return "3.0.2"
	case 0x0311:
		return "3.1.1"
	default:
		return fmt.Sprintf("0x%04x", dialect)
	}
}

func parseSMB1Dialects(smb []byte) ([]string, bool) {
	if len(smb) < 35 || smb[32] != 0 {
		return nil, false
	}
	byteCount := int(binary.LittleEndian.Uint16(smb[33:35]))
	if byteCount > maxSMBDialectBytes || 35+byteCount > len(smb) {
		return nil, false
	}
	body := smb[35 : 35+byteCount]
	var dialects []string
	for len(body) > 0 && len(dialects) < maxSMBDialects {
		if body[0] != 0x02 {
			return nil, false
		}
		body = body[1:]
		end := bytes.IndexByte(body, 0)
		if end < 0 || end > 128 {
			return nil, false
		}
		dialects = append(dialects, string(body[:end]))
		body = body[end+1:]
	}
	if len(body) != 0 || len(dialects) == 0 {
		return nil, false
	}
	return dialects, true
}

func (d *SMBDecoder) storeSMB1Dialects(state *flow.State, dialects []string) {
	if state == nil {
		return
	}
	key := smbNegotiationKey(state.Key)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.negotiations == nil {
		d.negotiations = make(map[string]smbNegotiation)
	}
	if len(d.negotiations) >= maxSMBNegotiationMap {
		var oldestKey string
		var oldest time.Time
		for candidate, negotiation := range d.negotiations {
			if oldest.IsZero() || negotiation.updated.Before(oldest) {
				oldestKey, oldest = candidate, negotiation.updated
			}
		}
		delete(d.negotiations, oldestKey)
	}
	d.negotiations[key] = smbNegotiation{dialects: append([]string(nil), dialects...), updated: time.Now()}
}

func (d *SMBDecoder) selectedSMB1Dialect(state *flow.State, smb []byte) (string, bool) {
	if state == nil || len(smb) < 35 || smb[32] != 1 {
		return "", false
	}
	index := int(binary.LittleEndian.Uint16(smb[33:35]))
	key := smbNegotiationKey(state.Key)
	d.mu.Lock()
	defer d.mu.Unlock()
	negotiation, ok := d.negotiations[key]
	delete(d.negotiations, key)
	if !ok || index >= len(negotiation.dialects) {
		return "", false
	}
	return negotiation.dialects[index], true
}

func smbNegotiationKey(key flow.Key) string {
	src := net.JoinHostPort(key.SrcIP.String(), fmt.Sprint(key.SrcPort))
	dst := net.JoinHostPort(key.DstIP.String(), fmt.Sprint(key.DstPort))
	if src > dst {
		src, dst = dst, src
	}
	return src + "|" + dst
}

// extractShareName attempts to find a UNC path (\\server\share) in the SMBv2
// TreeConnect request body. The path is encoded as UTF-16LE after the fixed
// header. Returns empty string if not found.
func (d *SMBDecoder) extractShareName(smb []byte) string {
	// SMBv2 TreeConnect request structure (after 64-byte header):
	//   StructureSize (2) + Reserved/Flags (2) + PathOffset (2) + PathLength (2)
	if len(smb) < 72 {
		return ""
	}
	pathOffset := int(binary.LittleEndian.Uint16(smb[68:70]))
	pathLength := int(binary.LittleEndian.Uint16(smb[70:72]))

	// PathOffset is relative to the beginning of the SMB2 header.
	if pathOffset < 64 || pathLength <= 0 || pathLength > 1024 {
		return ""
	}
	if pathOffset+pathLength > len(smb) {
		return ""
	}

	// UTF-16LE decode.
	pathBytes := smb[pathOffset : pathOffset+pathLength]
	if len(pathBytes)%2 != 0 {
		return ""
	}
	u16 := make([]uint16, len(pathBytes)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(pathBytes[i*2 : i*2+2])
	}
	runes := utf16.Decode(u16)
	// Cap output length.
	if len(runes) > 512 {
		runes = runes[:512]
	}
	return string(runes)
}

func smbV1CommandName(cmd byte) string {
	switch cmd {
	case 0x72:
		return "negotiate"
	case 0x73:
		return "session_setup"
	case 0x75:
		return "tree_connect"
	case 0x71:
		return "tree_disconnect"
	case 0x24:
		return "locking"
	case 0x2E:
		return "read"
	case 0x2F:
		return "write"
	case 0x04:
		return "close"
	case 0xA2:
		return "create"
	default:
		return "unknown"
	}
}
