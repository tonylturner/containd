package itdpi

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/containd/containd/pkg/dp/dpi"
	"github.com/containd/containd/pkg/dp/flow"
)

// TLSDecoder emits ClientHello metadata (SNI, ALPN when possible).
type TLSDecoder struct{}

func NewTLSDecoder() *TLSDecoder { return &TLSDecoder{} }

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
	if pkt == nil || len(pkt.Payload) < 6 {
		return nil, nil
	}
	p := pkt.Payload
	// TLS record: type(1)=0x16, version(2), length(2).
	if p[0] != 0x16 || len(p) < 5 {
		return nil, nil
	}
	recLen := int(binary.BigEndian.Uint16(p[3:5]))
	if 5+recLen > len(p) {
		recLen = len(p) - 5
	}
	rec := p[5 : 5+recLen]
	// Handshake: type(1)=0x01 ClientHello.
	if len(rec) < 4 || rec[0] != 0x01 {
		return nil, nil
	}
	hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
	if 4+hsLen > len(rec) {
		hsLen = len(rec) - 4
	}
	ch := rec[4 : 4+hsLen]
	meta := parseClientHello(ch)
	if meta.SNI == "" && meta.ALPN == "" && meta.JA3Hash == "" {
		return nil, nil
	}
	attrs := map[string]any{
		"sni":           meta.SNI,
		"alpn":          meta.ALPN,
		"tls_version":   meta.TLSVersion,
		"cipher_suites": meta.CipherSuites,
		"extensions":    meta.Extensions,
		"ja3":           meta.JA3,
		"ja3_hash":      meta.JA3Hash,
		"src_port":      pkt.SrcPort,
		"dst_port":      pkt.DstPort,
		"transport":     pkt.Proto,
	}
	ev := dpi.Event{
		FlowID:     state.Key.Hash(),
		Proto:      "tls",
		Kind:       "client_hello",
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
	return []dpi.Event{ev}, nil
}

func (d *TLSDecoder) OnFlowEnd(state *flow.State) ([]dpi.Event, error) { return nil, nil }

type clientHelloMeta struct {
	SNI          string
	ALPN         string
	TLSVersion   string
	CipherSuites []uint16
	Extensions   []uint16
	JA3          string
	JA3Hash      string
}

func parseClientHello(ch []byte) clientHelloMeta {
	off := 0
	if len(ch) < 2+32+1 {
		return clientHelloMeta{}
	}
	clientVersion := binary.BigEndian.Uint16(ch[0:2])
	off += 2 // client_version
	off += 32 // random
	if off >= len(ch) {
		return clientHelloMeta{}
	}
	sidLen := int(ch[off])
	off++
	off += sidLen
	if off+2 > len(ch) {
		return clientHelloMeta{}
	}
	csLen := int(binary.BigEndian.Uint16(ch[off : off+2]))
	off += 2
	csStart := off
	off += csLen
	if off >= len(ch) {
		return clientHelloMeta{}
	}
	compLen := int(ch[off])
	off++
	off += compLen
	if off+2 > len(ch) {
		return clientHelloMeta{}
	}
	extLen := int(binary.BigEndian.Uint16(ch[off : off+2]))
	off += 2
	if off+extLen > len(ch) {
		extLen = len(ch) - off
	}
	exts := ch[off : off+extLen]
	eoff := 0
	meta := clientHelloMeta{
		TLSVersion: tlsVersionString(clientVersion),
	}
	meta.CipherSuites = parseCipherSuites(ch[csStart : csStart+csLen])
	for eoff+4 <= len(exts) {
		typ := binary.BigEndian.Uint16(exts[eoff : eoff+2])
		l := int(binary.BigEndian.Uint16(exts[eoff+2 : eoff+4]))
		eoff += 4
		if eoff+l > len(exts) {
			break
		}
		body := exts[eoff : eoff+l]
		eoff += l
		meta.Extensions = append(meta.Extensions, typ)
		switch typ {
		case 0x0000: // server_name
			if name := parseSNI(body); name != "" {
				meta.SNI = name
			}
		case 0x0010: // ALPN
			if p := parseALPN(body); p != "" {
				meta.ALPN = p
			}
		}
	}
	meta.JA3 = buildJA3(clientVersion, meta.CipherSuites, meta.Extensions)
	if meta.JA3 != "" {
		sum := md5.Sum([]byte(meta.JA3))
		meta.JA3Hash = fmt.Sprintf("%x", sum)
	}
	return meta
}

func parseSNI(body []byte) string {
	if len(body) < 5 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(body[0:2]))
	if 2+listLen > len(body) {
		listLen = len(body) - 2
	}
	off := 2
	for off+3 <= 2+listLen {
		nameType := body[off]
		nameLen := int(binary.BigEndian.Uint16(body[off+1 : off+3]))
		off += 3
		if off+nameLen > len(body) {
			break
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
		listLen = len(body) - off
	}
	end := off + listLen
	var protos []string
	for off < end {
		if off >= len(body) {
			break
		}
		l := int(body[off])
		off++
		if off+l > len(body) {
			break
		}
		protos = append(protos, string(body[off:off+l]))
		off += l
		if len(protos) >= 3 {
			break
		}
	}
	return strings.Join(protos, ",")
}

func parseCipherSuites(buf []byte) []uint16 {
	if len(buf) < 2 || len(buf)%2 != 0 {
		return nil
	}
	out := make([]uint16, 0, len(buf)/2)
	for i := 0; i+1 < len(buf); i += 2 {
		out = append(out, binary.BigEndian.Uint16(buf[i:i+2]))
	}
	if len(out) > 50 {
		return out[:50]
	}
	return out
}

func buildJA3(version uint16, ciphers []uint16, exts []uint16) string {
	if len(ciphers) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%d,", version))
	for i, c := range ciphers {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(fmt.Sprintf("%d", c))
	}
	b.WriteByte(',')
	for i, e := range exts {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(fmt.Sprintf("%d", e))
	}
	// curves and point formats omitted in v1 (set empty fields).
	b.WriteString(",,")
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
