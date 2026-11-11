// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package itdpi

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// TLSDecoder emits ClientHello metadata (SNI, ALPN when possible).
type TLSDecoder struct {
	mu          sync.Mutex
	streams     map[tlsStreamKey]*tlsStream
	connections map[string]*tlsConnection
}

func NewTLSDecoder() *TLSDecoder { return &TLSDecoder{} }

// Ports implements dpi.PortHinter for port-based dispatch.
func (d *TLSDecoder) Ports() (tcpPorts, udpPorts []uint16) {
	return []uint16{443, 8443, 9443, 993, 995, 465}, nil
}

func (d *TLSDecoder) Supports(state *flow.State) bool {
	if state == nil {
		return false
	}
	if state.Key.Proto != 6 {
		return false
	}
	// Common TLS ports.
	switch state.Key.SrcPort {
	case 443, 8443, 9443, 993, 995, 465:
		return true
	}
	switch state.Key.DstPort {
	case 443, 8443, 9443, 993, 995, 465:
		return true
	}
	return false
}

func (d *TLSDecoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if state == nil || pkt == nil || len(pkt.Payload) == 0 || pkt.Payload[0] != 22 {
		return nil, nil
	}
	local := NewTLSDecoder()
	result, err := local.ParseStream(state, dpi.StreamView{Bytes: pkt.Payload})
	var events []dpi.Event
	for _, frame := range result.Frames {
		events = append(events, frame.Events...)
	}
	return events, err
}

func (d *TLSDecoder) OnFlowEnd(state *flow.State) ([]dpi.Event, error) { return nil, nil }

// ClientHelloSNI returns the visible SNI in a complete packet-local ClientHello.
// Exclusions must not use partial records.
// It works on every TCP port and does not reassemble fragmented handshakes.
func ClientHelloSNI(p []byte) string {
	if len(p) < 9 || p[0] != 0x16 || p[1] != 3 {
		return ""
	}
	n := int(binary.BigEndian.Uint16(p[3:5]))
	if n < 4 || n > len(p)-5 || p[5] != 1 {
		return ""
	}
	hs := int(p[6])<<16 | int(p[7])<<8 | int(p[8])
	if hs > n-4 {
		return ""
	}
	return parseClientHello(p[9 : 9+hs]).SNI
}

type clientHelloMeta struct {
	SNI             string
	ALPN            string
	LegacyVersion   string
	OfferedVersions []string
	CipherSuites    []uint16
	Extensions      []uint16
	JA3             string
	JA3Hash         string
}

func parseClientHello(ch []byte) clientHelloMeta {
	if len(ch) < 35 || len(ch) > maxTLSHello {
		return clientHelloMeta{}
	}
	version := binary.BigEndian.Uint16(ch[:2])
	off := 35 + int(ch[34])
	if off+2 > len(ch) {
		return clientHelloMeta{}
	}
	n := int(binary.BigEndian.Uint16(ch[off:]))
	off += 2
	if n == 0 || n%2 != 0 || off+n >= len(ch) {
		return clientHelloMeta{}
	}
	meta := clientHelloMeta{LegacyVersion: tlsVersionString(version), CipherSuites: parseCipherSuites(ch[off : off+n])}
	off += n
	n = int(ch[off])
	off++
	if n == 0 || off+n > len(ch) {
		return clientHelloMeta{}
	}
	off += n
	var curves, points []uint16
	if off < len(ch) {
		if off+2 > len(ch) {
			return clientHelloMeta{}
		}
		n = int(binary.BigEndian.Uint16(ch[off:]))
		off += 2
		if off+n != len(ch) {
			return clientHelloMeta{}
		}
		for off < len(ch) {
			if off+4 > len(ch) {
				return clientHelloMeta{}
			}
			typ := binary.BigEndian.Uint16(ch[off:])
			n = int(binary.BigEndian.Uint16(ch[off+2:]))
			off += 4
			if off+n > len(ch) {
				return clientHelloMeta{}
			}
			body := ch[off : off+n]
			off += n
			if !isGREASE(typ) {
				meta.Extensions = append(meta.Extensions, typ)
			}
			switch typ {
			case 0:
				meta.SNI = parseSNI(body)
			case 16:
				meta.ALPN = parseALPN(body)
			case 10:
				if len(body) < 2 || int(binary.BigEndian.Uint16(body)) != len(body)-2 || len(body)%2 != 0 {
					return clientHelloMeta{}
				}
				curves = parseCipherSuites(body[2:])
			case 11:
				if len(body) < 1 || int(body[0]) != len(body)-1 {
					return clientHelloMeta{}
				}
				points = nil
				for _, p := range body[1:] {
					points = append(points, uint16(p))
				}
			case 43:
				if len(body) < 3 || int(body[0]) != len(body)-1 || len(body)%2 != 1 {
					return clientHelloMeta{}
				}
				for _, v := range parseCipherSuites(body[1:]) {
					meta.OfferedVersions = append(meta.OfferedVersions, tlsVersionString(v))
				}
			}
		}
	}
	meta.JA3 = buildJA3(version, meta.CipherSuites, meta.Extensions, curves, points)
	sum := md5.Sum([]byte(meta.JA3)) // nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-md5 -- JA3 standardizes MD5, not used for security.
	meta.JA3Hash = fmt.Sprintf("%x", sum)
	return meta
}

func parseSNI(body []byte) string {
	if len(body) < 5 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(body[0:2]))
	if 2+listLen != len(body) {
		return ""
	}
	off := 2
	for off+3 <= 2+listLen {
		nameType := body[off]
		nameLen := int(binary.BigEndian.Uint16(body[off+1 : off+3]))
		off += 3
		if off+nameLen > 2+listLen {
			return ""
		}
		if nameType == 0 {
			return string(bytes.ToLower(body[off : off+nameLen]))
		}
		off += nameLen
	}
	return ""
}

func parseALPN(body []byte) string {
	if len(body) < 3 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(body[0:2]))
	off := 2
	if off+listLen > len(body) {
		return ""
	}
	end := off + listLen
	var protos []string
	for off < end {
		if off >= len(body) {
			break
		}
		l := int(body[off])
		off++
		if l == 0 || off+l > end {
			return ""
		}
		protos = append(protos, string(body[off:off+l]))
		off += l
	}
	return strings.Join(protos, ",")
}

func parseCipherSuites(buf []byte) []uint16 {
	if len(buf) < 2 || len(buf)%2 != 0 {
		return nil
	}
	out := make([]uint16, 0, len(buf)/2)
	for i := 0; i+1 < len(buf); i += 2 {
		v := binary.BigEndian.Uint16(buf[i : i+2])
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

// RFC 8701 reserves the sixteen equal-byte values 0x0a0a through 0xfafa.
func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && byte(v) == byte(v>>8) }

func buildJA3(version uint16, lists ...[]uint16) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d", version)
	for _, list := range lists {
		b.WriteByte(',')
		for i, v := range list {
			if i > 0 {
				b.WriteByte('-')
			}
			fmt.Fprintf(&b, "%d", v)
		}
	}
	return b.String()
}

func tlsVersionString(v uint16) string {
	switch v {
	case 0x0301:
		return "TLS1.0"
	case 0x0302:
		return "TLS1.1"
	case 0x0303:
		return "TLS1.2"
	case 0x0304:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
