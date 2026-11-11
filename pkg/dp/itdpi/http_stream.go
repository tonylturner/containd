// SPDX-License-Identifier: Apache-2.0

package itdpi

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

const maxHTTPHeaders = 32 * 1024
const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

type httpStreamKey struct {
	session string
	dir     dpi.StreamDir
}

const maxHTTPRequestMethods = 64

type httpConnection struct {
	refs                   int
	methods                []string
	opaque, connectPending bool
}

type httpStream struct {
	connection                     string
	peer                           *httpConnection
	anchored, stopped, requestSide bool
	scan, lineStart                int

	h2         *h2Stream
	remaining  uint64
	chunked    bool
	chunkCRLF  bool
	trailers   bool
	untilClose bool
}

func (*HTTPDecoder) Protocol() string { return "http" }
func (d *HTTPDecoder) StreamEnded(session string, dir dpi.StreamDir) {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := httpStreamKey{session, dir}
	if s := d.streams[key]; s != nil {
		s.peer.refs--
		if s.peer.refs == 0 {
			delete(d.connections, s.connection)
		}
		delete(d.streams, key)
	}
}

func (d *HTTPDecoder) ParseStream(st *flow.State, v dpi.StreamView) (dpi.StreamResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.streams == nil {
		d.streams = make(map[httpStreamKey]*httpStream)
		d.connections = make(map[string]*httpConnection)
	}
	key := httpStreamKey{v.Session, v.Dir}
	s := d.streams[key]
	if s == nil {
		connection := metadataConnectionKey(st, v)
		peer := d.connections[connection]
		if peer == nil {
			peer = &httpConnection{}
			d.connections[connection] = peer
		}
		peer.refs++
		s = &httpStream{connection: connection, peer: peer}
		d.streams[key] = s
	}
	var res dpi.StreamResult
	for res.Consumed < len(v.Bytes) {
		off := res.Consumed
		p := v.Bytes[off:]
		n, events, err := d.httpFrame(st, s, p)
		if err != nil {
			s.stopped = true
			s.h2 = nil
			metadataStop(st, v, &res, s.anchored, "http", err.Error(), nil)
			break
		}
		if n == 0 {
			break
		}
		metadataFrame(&res, v, n, events)
	}
	res.NeedMore = res.Consumed < len(v.Bytes)
	return res, nil
}

func (d *HTTPDecoder) httpFrame(st *flow.State, s *httpStream, p []byte) (int, []dpi.Event, error) {
	if s.stopped || s.peer.opaque {
		return len(p), nil, nil
	}
	if s.h2 != nil {
		return s.h2.frame(st, p)
	}
	if s.untilClose {
		return len(p), nil, nil
	}
	if s.remaining > 0 {
		n := min(uint64(len(p)), s.remaining)
		s.remaining -= n
		return int(n), nil, nil
	}
	if s.chunkCRLF {
		if p[0] == '\n' {
			s.chunkCRLF = false
			return 1, nil, nil
		}
		if len(p) < 2 {
			return 0, nil, nil
		}
		if !bytes.HasPrefix(p, []byte("\r\n")) {
			return 0, nil, fmt.Errorf("invalid HTTP chunk delimiter")
		}
		s.chunkCRLF = false
		return 2, nil, nil
	}
	if s.trailers {
		n, err := s.headerEnd(p, false)
		if err != nil || n == 0 {
			return 0, nil, err
		}
		s.trailers = false
		return n, nil, nil
	}

	if s.chunked {
		n := bytes.IndexByte(p, '\n')
		if n < 0 {
			if len(p) > 1024 {
				return 0, nil, fmt.Errorf("HTTP chunk line limit")
			}
			return 0, nil, nil
		}
		if n > 1024 {
			return 0, nil, fmt.Errorf("HTTP chunk line limit")
		}
		line := bytes.TrimSuffix(p[:n], []byte("\r"))
		size, err := strconv.ParseUint(strings.SplitN(string(line), ";", 2)[0], 16, 64)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid HTTP chunk size")
		}
		if size == 0 {
			s.chunked = false
			s.trailers = true
		} else {
			s.remaining = size
			s.chunkCRLF = true
		}
		return n + 1, nil, nil
	}
	if p[0] == 'P' && bytes.HasPrefix([]byte(h2Preface), p[:min(len(p), len(h2Preface))]) {
		if len(p) < len(h2Preface) {
			return 0, nil, nil
		}
		s.h2 = newH2Stream()
		s.anchored = true
		return len(h2Preface), []dpi.Event{{FlowID: st.ID(), Proto: "http2", Kind: "preface", Attributes: httpTransport(st)}}, nil
	}
	// The server connection preface begins with SETTINGS, not the magic string.
	// This also permits reply-first passive capture without inventing headers.
	if p[0] == 0 {
		if len(p) < 9 {
			return 0, nil, nil
		}
		if p[3] == 4 {
			s.h2 = newH2Stream()
			n, events, err := s.h2.frame(st, p)
			if err == nil && n > 0 {
				s.anchored = true
			}
			return n, events, err
		}
	}
	// Leading empty lines before a request are ignored (RFC 9112 2.2).
	if p[0] == '\n' {
		return 1, nil, nil
	}
	if p[0] == '\r' && len(p) == 1 {
		return 0, nil, nil
	}
	if bytes.HasPrefix(p, []byte("\r\n")) {
		return 2, nil, nil
	}
	// CONNECT clients must wait for the server's final response. Their early
	// tunnel bytes are not another HTTP request, including before a 2xx arrives.
	if s.peer.connectPending && s.requestSide {
		return len(p), nil, nil
	}
	end, err := s.headerEnd(p, true)
	if err != nil || end == 0 {
		return 0, nil, err
	}
	line, headers := parseHTTP(p[:end])
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return 0, nil, fmt.Errorf("invalid HTTP start line")
	}
	if err := validateHTTPFraming(p[:end], headers); err != nil {
		return 0, nil, err
	}
	response := strings.HasPrefix(line, "HTTP/")
	status := 0
	method := ""
	if response {
		var err error
		status, err = strconv.Atoi(parts[1])
		if err != nil || status < 100 || status > 599 {
			return 0, nil, fmt.Errorf("invalid HTTP response status")
		}
		if len(s.peer.methods) > 0 {
			method = s.peer.methods[0]
		}
	} else {
		method = parts[0]
		s.requestSide = true
	}
	events := http1Events(st, &dpi.ParsedPacket{Payload: p[:end], Proto: "tcp", SrcPort: st.Key.SrcPort, DstPort: st.Key.DstPort})
	switch {
	case response && status == 101:
		if strings.EqualFold(headers["upgrade"], "h2c") {
			s.h2 = newH2Stream()
		} else {
			s.peer.opaque = true
		}
	case response && method == "CONNECT" && status >= 200 && status < 300:
		s.peer.opaque = true
	case response && (method == "HEAD" || status < 200 || status == 204 || status == 304):
		// Content-Length here describes a representation, never wire body bytes.
	case headers["transfer-encoding"] != "":
		if !strings.EqualFold(headers["transfer-encoding"], "chunked") {
			return 0, nil, fmt.Errorf("unsupported HTTP transfer encoding")
		}
		s.chunked = true
	case headers["content-length"] != "":
		n, err := strconv.ParseUint(headers["content-length"], 10, 64)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid HTTP content length")
		}
		s.remaining = n
	case response:
		s.untilClose = true
	}
	if response {
		if status >= 200 || status == 101 {
			if len(s.peer.methods) > 0 {
				s.peer.methods[0] = ""
				s.peer.methods = s.peer.methods[1:]
			}
			if method == "CONNECT" {
				s.peer.connectPending = false
			}
		}
	} else {
		if len(s.peer.methods) >= maxHTTPRequestMethods {
			s.peer.opaque = true
			return 0, nil, fmt.Errorf("HTTP request correlation limit")
		}
		// Retain only the method token, not its backing request line and path.
		s.peer.methods = append(s.peer.methods, strings.Clone(method))
		if method == "CONNECT" {
			s.peer.connectPending = true
		}
	}

	return end, events, nil
}

func httpTransport(st *flow.State) map[string]any {
	return map[string]any{"src_port": st.Key.SrcPort, "dst_port": st.Key.DstPort, "transport": "tcp"}
}

func validateHTTPFraming(raw []byte, headers map[string]string) error {
	if headers["transfer-encoding"] != "" && headers["content-length"] != "" {
		return fmt.Errorf("ambiguous HTTP body framing")
	}
	var lengthSeen bool
	lines := bytes.Split(raw, []byte("\n"))
	for _, line := range lines[1:] {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			return fmt.Errorf("folded HTTP header")
		}
		i := bytes.IndexByte(line, ':')
		if i <= 0 {
			return fmt.Errorf("invalid HTTP header")
		}
		name := strings.ToLower(string(line[:i]))
		if strings.TrimSpace(name) != name {
			return fmt.Errorf("invalid HTTP header name")
		}
		if name == "content-length" {
			if lengthSeen {
				return fmt.Errorf("duplicate HTTP content length")
			}
			lengthSeen = true
		}
	}
	return nil
}

// Scan newly arrived bytes only. Retain offsets, never the manager's buffer.
// Both CRLF and bare LF terminate header lines, as supported by parseHTTP.
func (s *httpStream) headerEnd(p []byte, startLine bool) (int, error) {
	for s.scan < len(p) {
		i := bytes.IndexByte(p[s.scan:], '\n')
		if i < 0 {
			s.scan = len(p)
			break
		}
		i += s.scan
		if i+1 > maxHTTPHeaders {
			return 0, fmt.Errorf("HTTP header limit")
		}
		line := bytes.TrimSuffix(p[s.lineStart:i], []byte("\r"))
		if len(line) == 0 {
			s.scan = 0
			s.lineStart = 0
			return i + 1, nil
		}
		if startLine && s.lineStart == 0 {
			if !looksLikeHTTPLine(strings.TrimSpace(string(line))) {
				return 0, fmt.Errorf("invalid HTTP start line")
			}
			s.anchored = true
		}
		s.scan = i + 1
		s.lineStart = i + 1
	}
	if len(p) > maxHTTPHeaders {
		return 0, fmt.Errorf("HTTP header limit")
	}
	return 0, nil
}
