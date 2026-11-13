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

type tlsConnection struct {
	refs     int
	selected string
}

type tlsStream struct {
	connection                             string
	peer                                   *tlsConnection
	anchored, stopped, encrypted, offers13 bool
	header                                 [4]byte
	headerN                                int
	typ                                    byte
	remaining                              int
	hello                                  []byte
}

func (d *TLSDecoder) StreamEnded(session string, dir dpi.StreamDir) {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := tlsStreamKey{session, dir}
	if s := d.streams[key]; s != nil {
		s.peer.refs--
		if s.peer.refs == 0 {
			delete(d.connections, s.connection)
		}
		delete(d.streams, key)
	}
}

func (d *TLSDecoder) ParseStream(state *flow.State, v dpi.StreamView) (dpi.StreamResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.streams == nil {
		d.streams = make(map[tlsStreamKey]*tlsStream)
		d.connections = make(map[string]*tlsConnection)
	}
	key := tlsStreamKey{v.Session, v.Dir}
	s := d.streams[key]
	if s == nil {
		connection := metadataConnectionKey(state, v)
		peer := d.connections[connection]
		if peer == nil {
			peer = &tlsConnection{}
			d.connections[connection] = peer
		}
		peer.refs++
		s = &tlsStream{connection: connection, peer: peer}
		d.streams[key] = s
	}
	var res dpi.StreamResult
	for res.Consumed < len(v.Bytes) {
		if s.stopped || s.encrypted {
			metadataFrame(&res, v, len(v.Bytes)-res.Consumed, nil)
			break
		}
		p := v.Bytes[res.Consumed:]
		if len(p) < 5 {
			break
		}
		n := int(binary.BigEndian.Uint16(p[3:5]))
		reason := ""
		var prior []dpi.Event
		if p[0] < 20 || p[0] > 24 || p[1] != 3 || n > 18432 {
			reason = "invalid TLS record"
		} else if len(p) < 5+n {
			break
		} else {
			s.anchored = true
			switch p[0] {
			case 22:
				events, err := s.handshake(state, p[5:5+n])
				if err != "" {
					reason = err
					prior = events
				} else {
					metadataFrame(&res, v, 5+n, events)
				}
			case 20:
				if n != 1 || p[5] != 1 {
					reason = "invalid TLS ChangeCipherSpec"
				} else {
					// A TLS 1.3 dummy CCS does not encrypt subsequent retry hellos.
					// A captured server selection takes precedence over a client offer.
					tls13 := s.peer.selected == "TLS1.3" || s.peer.selected == "" && s.offers13
					if !tls13 {
						s.encrypted = true
						s.hello = nil
					}
					metadataFrame(&res, v, 5+n, nil)
				}
			default:
				if s.headerN != 0 || s.remaining != 0 {
					reason = "interrupted TLS handshake"
				} else {
					metadataFrame(&res, v, 5+n, nil)
				}
			}
		}
		if reason != "" {
			s.stopped = true
			s.hello = nil
			metadataStop(state, v, &res, s.anchored, "tls", reason, prior)
		}
	}
	res.NeedMore = res.Consumed < len(v.Bytes)
	return res, nil
}

// Consume each record once. Only hello bodies are retained; Certificate and
// other potentially large messages are skipped by their 24-bit wire length.
func (s *tlsStream) handshake(st *flow.State, p []byte) ([]dpi.Event, string) {
	var events []dpi.Event
	for len(p) > 0 {
		if s.headerN < 4 {
			n := copy(s.header[s.headerN:], p)
			s.headerN += n
			p = p[n:]
			if s.headerN < 4 {
				break
			}
			s.typ = s.header[0]
			s.remaining = int(s.header[1])<<16 | int(s.header[2])<<8 | int(s.header[3])
			if s.typ == 1 || s.typ == 2 {
				if s.remaining > maxTLSHello {
					return events, "TLS hello size limit"
				}
				s.hello = s.hello[:0]
			}
		}
		n := min(len(p), s.remaining)
		if s.typ == 1 || s.typ == 2 {
			s.hello = append(s.hello, p[:n]...)
		}
		s.remaining -= n
		p = p[n:]
		if s.remaining != 0 {
			break
		}
		if s.typ == 1 || s.typ == 2 {
			ev, ok := tlsHelloEvent(st, s.typ, s.hello)
			if !ok {
				return events, "invalid TLS hello"
			}
			events = append(events, ev)
			if s.typ == 1 {
				s.offers13 = false
				for _, version := range ev.Attributes["tls_offered_versions"].([]string) {
					if version == "TLS1.3" {
						s.offers13 = true
					}
				}
			} else {
				s.peer.selected = ev.Attributes["tls_selected_version"].(string)
			}
			s.hello = nil
		}
		s.headerN = 0
	}
	return events, ""
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
