// SPDX-License-Identifier: Apache-2.0

package itdpi

import (
	"bytes"
	"errors"
	"fmt"
	"mime"
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

type httpStream struct {
	id                uint64
	memory            *flow.InspectionMemory
	enforcing         bool
	failure           *dpi.StreamError
	key               httpStreamKey
	connection        string
	peer              *httpConnection
	anchored, resync  bool
	suppressMalformed bool
	scan, lineStart   int
	role              dpi.StreamDir
	body              *httpBody

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
		s.dropH2()
		s.clearFraming()
		delete(s.peer.streams, key)
		if len(s.peer.streams) == 0 {
			s.peer.clearRequests()
			delete(d.connections, s.connection)
			s.peer.memory.Release()
		}
		delete(d.streams, key)
		s.memory.Release()
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
		var err error
		s, err = d.admit(st, v)
		if err != nil {
			return dpi.StreamResult{}, err
		}
	}
	if s.failure != nil {
		return dpi.StreamResult{}, s.failure
	}
	if v.Role != dpi.DirUnknown {
		if !s.peer.acceptsStart(s.id, v.Role == dpi.ServerToClient) {
			s.peer.clearRequests()
			s.peer.dropped = 0
			s.peer.clientKnown, s.peer.serverKnown = false, false
			s.peer.uncertain = true
		}
		s.peer.transportKey, s.peer.transportRole = s.id, v.Role
	}
	s.role = s.peer.role(s.id)
	var res dpi.StreamResult
	d.httpReanchor(st, s, v, &res)
	for res.Consumed < len(v.Bytes) {
		off := res.Consumed
		p := v.Bytes[off:]
		n, events, err := d.httpFrame(st, s, p)
		if err != nil {
			if errors.Is(err, flow.ErrInspectionLimit) {
				return dpi.StreamResult{}, s.stateLimit(d.resources, v.Base+int64(off))
			}
			anchored := s.anchored
			s.clearFraming()
			s.resync = true
			s.dropH2()
			s.anchored = false
			s.suppressMalformed = true
			s.peer.uncertain = true
			metadataStop(st, v, &res, anchored, "http", err.Error(), nil)
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
	if s.resync {
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
		if s.remaining == 0 && !s.chunked && s.body != nil {
			s.body.incomplete = false
		}
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
		if s.body != nil {
			s.body.incomplete = false
		}
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
		digits := strings.SplitN(string(line), ";", 2)[0]
		if digits == "" || strings.IndexFunc(digits, func(c rune) bool {
			return !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F')
		}) >= 0 {
			return 0, nil, fmt.Errorf("invalid HTTP chunk size")
		}
		size, err := strconv.ParseUint(digits, 16, 64)
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
		var err error
		s.h2, err = newH2Stream(s.memory)
		if err != nil {
			return 0, nil, err
		}
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
			var err error
			s.h2, err = newH2Stream(s.memory)
			if err != nil {
				return 0, nil, err
			}
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
	end, err := s.headerEnd(p, true)
	if err != nil || end == 0 {
		return 0, nil, err
	}
	line, headers := parseHTTP(p[:end])
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return 0, nil, fmt.Errorf("invalid HTTP start line")
	}
	response := strings.HasPrefix(line, "HTTP/")
	if s.role != dpi.DirUnknown && response != (s.role == dpi.ServerToClient) ||
		s.role == dpi.DirUnknown && !s.peer.acceptsStart(s.id, response) {
		// Wrong-role text is not a message from this HTTP endpoint. It
		// cannot dequeue requests, switch protocols or frame a peer's body.
		return end, nil, nil
	}
	if err := validateHTTPFraming(p[:end], headers); err != nil {
		return 0, nil, err
	}
	status := 0
	method := ""
	pending := s.peer.pending()
	if response {
		var err error
		status, err = strconv.Atoi(parts[1])
		if err != nil || status < 100 || status > 599 {
			return 0, nil, fmt.Errorf("invalid HTTP response status")
		}
		method = pending.method
	} else {
		method = parts[0]
	}
	events := http1Events(st, &dpi.ParsedPacket{Payload: p[:end], Proto: "tcp", SrcPort: st.Key.SrcPort, DstPort: st.Key.DstPort})
	uncertainBody := response && (s.peer.uncertain || s.peer.dropped != 0 && len(s.peer.methods) == 0)
	switch {
	case response && status == 101 && !s.peer.uncertain && s.peer.dropped == 0 && pending.acceptsUpgrade(headers):
		if strings.EqualFold(headers["upgrade"], "h2c") {
			var err error
			s.h2, err = newH2Stream(s.memory)
			if err != nil {
				return 0, nil, err
			}
		} else {
			d.httpTunnel(s.peer)
		}
	case response && method == "CONNECT" && status >= 200 && status < 300 && !s.peer.uncertain && s.peer.dropped == 0:
		d.httpTunnel(s.peer)
	case response && (status < 200 || status == 204 || status == 304):
		// Content-Length here describes a representation, never wire body bytes.
	case uncertainBody && headers["content-length"] != "0":
		// The lost method might be HEAD. Do not treat a speculative next
		// packet boundary as evidence that outstanding replies have drained.
		s.untilClose = true
		s.peer.uncertain = true
	case response && method == "HEAD":
		// Only a followed correlation boundary establishes a HEAD reply.
	case headers["transfer-encoding"] != "":
		if httpChunked(headers["transfer-encoding"]) {
			s.chunked = true
		} else {
			s.untilClose = true // response with non-final-chunked coding
		}
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
		if status != 101 && !s.peer.clientKnown && !s.peer.serverKnown {
			s.peer.server, s.peer.serverKnown = s.id, true
		}
		if status >= 200 || status == 101 {
			s.peer.response()
		}
	} else {
		if err := s.peer.request(s, method, headers); err != nil {
			return 0, nil, err
		}
		if s.remaining > 0 || s.chunked {
			s.body = &httpBody{incomplete: true}
			if n := len(s.peer.methods); s.peer.dropped == 0 && n > 0 {
				s.peer.methods[n-1].body = s.body
			}
		}
	}
	s.anchored = !s.resync
	s.suppressMalformed = s.resync
	return end, events, nil
}

func httpTransport(st *flow.State) map[string]any {
	return map[string]any{"src_port": st.Key.SrcPort, "dst_port": st.Key.DstPort, "transport": "tcp"}
}

func validateHTTPFraming(raw []byte, headers map[string]string) error {
	if headers["transfer-encoding"] != "" && headers["content-length"] != "" {
		return fmt.Errorf("ambiguous HTTP body framing")
	}
	if length, ok := headers["content-length"]; ok {
		if length == "" || strings.IndexFunc(length, func(c rune) bool { return c < '0' || c > '9' }) >= 0 {
			return fmt.Errorf("invalid HTTP content length")
		}
		if _, err := strconv.ParseUint(length, 10, 64); err != nil {
			return fmt.Errorf("invalid HTTP content length")
		}
	}
	if coding, ok := headers["transfer-encoding"]; ok {
		parts, err := httpTransferCodings(coding)
		if err != nil {
			return err
		}
		seenChunked := false
		for i, name := range parts {
			if seenChunked {
				return fmt.Errorf("invalid HTTP transfer encoding")
			}
			if strings.EqualFold(name, "chunked") {
				seenChunked = true
				if i != len(parts)-1 {
					return fmt.Errorf("non-final chunked transfer encoding")
				}
			}
		}
		if !strings.HasPrefix(string(raw), "HTTP/") && !seenChunked {
			return fmt.Errorf("request transfer encoding is not chunked")
		}
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
		name := string(line[:i])
		if !httpProtocolToken(name) {
			return fmt.Errorf("invalid HTTP header name")
		}
		name = strings.ToLower(name)
		if name == "content-length" {
			if lengthSeen {
				return fmt.Errorf("duplicate HTTP content length")
			}
			lengthSeen = true
		}
	}
	return nil
}

// Quoted transfer parameters can contain commas; field combination must happen
// before splitting the coding list. Chunked itself has no parameters.
func httpTransferCodings(value string) ([]string, error) {
	var names []string
	start, quoted, escaped := 0, false, false
	for i := 0; i <= len(value); i++ {
		if i < len(value) {
			c := value[i]
			if escaped {
				escaped = false
				continue
			}
			if quoted && c == '\\' {
				escaped = true
				continue
			}
			if c == '"' {
				quoted = !quoted
			}
			if c != ',' || quoted {
				continue
			}
		}
		part := strings.Trim(value[start:i], " \t")
		token, _, _ := strings.Cut(part, ";")
		if !httpProtocolToken(strings.Trim(token, " \t")) {
			return nil, fmt.Errorf("invalid HTTP transfer encoding")
		}
		name, params, err := mime.ParseMediaType(part)
		if err != nil || !httpProtocolToken(name) || name == "chunked" && len(params) != 0 {
			return nil, fmt.Errorf("invalid HTTP transfer encoding")
		}
		names = append(names, name)
		start = i + 1
	}
	return names, nil
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
			if !looksLikeHTTPLine(string(line)) {
				return 0, fmt.Errorf("invalid HTTP start line")
			}
			if !s.suppressMalformed {
				s.anchored = true
			}
		}
		s.scan = i + 1
		s.lineStart = i + 1
	}
	if len(p) > maxHTTPHeaders {
		return 0, fmt.Errorf("HTTP header limit")
	}
	return 0, nil
}
