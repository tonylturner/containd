// SPDX-License-Identifier: Apache-2.0

package itdpi

import (
	"encoding/binary"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// Bound the whole handshake, never individual JA3 lists. The manager bounds
// incomplete TCP data separately. TLS plaintext records are at most 2^14 bytes.
const maxTLSHello = 64 * 1024

func (*TLSDecoder) Protocol() string { return "tls" }

type tlsStreamKey struct {
	session string
	dir     dpi.StreamDir
}

func (d *TLSDecoder) StreamEnded(session string, dir dpi.StreamDir) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.encrypted, tlsStreamKey{session, dir})
}

func (d *TLSDecoder) ParseStream(state *flow.State, v dpi.StreamView) (dpi.StreamResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.encrypted == nil {
		d.encrypted = make(map[tlsStreamKey]bool)
	}
	key := tlsStreamKey{v.Session, v.Dir}
	encrypted := d.encrypted[key]

	var res dpi.StreamResult
	var handshake []byte
	var events []dpi.Event
	start := 0
	for off := 0; off < len(v.Bytes); {
		p := v.Bytes[off:]
		if len(p) < 5 {
			break
		}
		n := int(binary.BigEndian.Uint16(p[3:5]))
		if p[0] < 20 || p[0] > 24 || p[1] != 3 || n > 18432 {
			return res, &dpi.FrameError{Offset: v.Base + int64(start), Reason: "invalid TLS record"}
		}
		if len(p) < 5+n {
			break
		}
		off += 5 + n
		if p[0] == 20 && len(handshake) == 0 {
			encrypted = true
			d.encrypted[key] = true
		}
		if p[0] == 22 && !encrypted {
			if len(handshake)+n > maxTLSHello+4 {
				return res, &dpi.FrameError{Offset: v.Base + int64(start), Reason: "TLS handshake size limit"}
			}
			handshake = append(handshake, p[5:5+n]...)
			for len(handshake) >= 4 {
				size := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
				if size > maxTLSHello {
					return res, &dpi.FrameError{Offset: v.Base + int64(start), Reason: "TLS handshake size limit"}
				}
				if len(handshake) < size+4 {
					break
				}
				if ev, ok := tlsHelloEvent(state, handshake[0], handshake[4:4+size]); ok {
					events = append(events, ev)
				}
				handshake = handshake[4+size:]
			}
		} else if len(handshake) != 0 {
			// Only ChangeCipherSpec may intervene in a fragmented handshake.
			if p[0] != 20 {
				return res, &dpi.FrameError{Offset: v.Base + int64(start), Reason: "interrupted TLS handshake"}
			}
		}
		if len(handshake) == 0 {
			res.Frames = append(res.Frames, dpi.DecodedFrame{Start: v.Base + int64(start), End: v.Base + int64(off), Events: events})
			res.Consumed = off
			start = off
			events = nil
		}
	}
	res.NeedMore = res.Consumed < len(v.Bytes)
	return res, nil
}

func tlsHelloEvent(state *flow.State, typ byte, body []byte) (dpi.Event, bool) {
	attrs := map[string]any{"transport": "tcp", "src_port": state.Key.SrcPort, "dst_port": state.Key.DstPort}
	kind := ""
	switch typ {
	case 1:
		m := parseClientHello(body)
		if m.JA3Hash == "" {
			return dpi.Event{}, false
		}
		kind = "client_hello"
		attrs["sni"], attrs["alpn"] = m.SNI, m.ALPN
		attrs["tls_legacy_version"], attrs["tls_offered_versions"] = m.LegacyVersion, m.OfferedVersions
		attrs["cipher_suites"], attrs["extensions"] = m.CipherSuites, m.Extensions
		attrs["ja3"], attrs["ja3_hash"] = m.JA3, m.JA3Hash
	case 2:
		legacy, selected, ok := parseServerHello(body)
		if !ok {
			return dpi.Event{}, false
		}
		kind = "server_hello"
		attrs["tls_legacy_version"], attrs["tls_selected_version"] = tlsVersionString(legacy), tlsVersionString(selected)
	default:
		return dpi.Event{}, false
	}
	return dpi.Event{FlowID: state.ID(), Proto: "tls", Kind: kind, Attributes: attrs}, true
}

func parseServerHello(b []byte) (uint16, uint16, bool) {
	if len(b) < 38 {
		return 0, 0, false
	}
	legacy := binary.BigEndian.Uint16(b)
	selected := legacy
	off := 35 + int(b[34]) + 3 // session ID, cipher suite and compression
	if off > len(b) {
		return 0, 0, false
	}
	if off == len(b) {
		return legacy, selected, true
	}
	if off+2 > len(b) || int(binary.BigEndian.Uint16(b[off:])) != len(b)-off-2 {
		return 0, 0, false
	}
	off += 2
	for off < len(b) {
		if off+4 > len(b) {
			return 0, 0, false
		}
		typ := binary.BigEndian.Uint16(b[off:])
		n := int(binary.BigEndian.Uint16(b[off+2:]))
		off += 4
		if off+n > len(b) {
			return 0, 0, false
		}
		if typ == 43 {
			if n != 2 {
				return 0, 0, false
			}
			selected = binary.BigEndian.Uint16(b[off:])
			if isGREASE(selected) {
				return 0, 0, false
			}
		}
		off += n
	}
	return legacy, selected, true
}
