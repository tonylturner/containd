// SPDX-License-Identifier: Apache-2.0

package itdpi

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// A recovery candidate must be a complete, valid start line at the actual
// beginning of this packet, not a substring of previously accumulated bytes.
func httpStart(p []byte) (response, valid bool) {
	end := bytes.IndexByte(p, '\n')
	if end < 0 {
		return false, false
	}
	line := strings.TrimSuffix(string(p[:end]), "\r")
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return false, false
	}
	if parts[0] == "HTTP/1.0" || parts[0] == "HTTP/1.1" {
		n, err := strconv.Atoi(parts[1])
		return true, err == nil && len(parts[1]) == 3 && n >= 100 && n <= 599 &&
			strings.IndexFunc(parts[2], func(c rune) bool { return c < 32 && c != '\t' || c == 127 }) < 0
	}
	return false, httpProtocolToken(parts[0]) && parts[1] != "" &&
		strings.IndexFunc(parts[1], func(c rune) bool { return c <= 32 || c == 127 }) < 0 &&
		(parts[2] == "HTTP/1.0" || parts[2] == "HTTP/1.1")
}

func httpChunked(coding string) bool {
	parts := strings.Split(coding, ",")
	return strings.EqualFold(strings.TrimSpace(parts[len(parts)-1]), "chunked")
}

func httpCommonRequest(p []byte) bool {
	method, _, _ := strings.Cut(string(p[:bytes.IndexByte(p, '\n')]), " ")
	switch method {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH":
		return true
	}
	return false
}

func (s *httpStream) declaredBody() bool {
	return s.remaining > 0 || s.chunked || s.chunkCRLF || s.trailers
}

func (s *httpStream) clearFraming() {
	s.scan, s.lineStart = 0, 0
	s.remaining = 0
	s.chunked, s.chunkCRLF, s.trailers, s.untilClose = false, false, false, false
	s.body = nil
}

func (d *HTTPDecoder) ResyncStream(st *flow.State, v dpi.StreamView, cause *dpi.StreamError) []dpi.Event {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.streams[httpStreamKey{v.Session, v.Dir}]
	if s == nil {
		return nil // unanchored capture loss is not malformed HTTP
	}
	var events []dpi.Event
	if s.anchored {
		events = []dpi.Event{{FlowID: st.ID(), Proto: "http", Kind: "malformed",
			Attributes: map[string]any{"error": cause.Error()}}}
	}
	s.clearFraming()
	s.resync, s.suppressMalformed, s.anchored = true, true, false
	s.h2 = nil
	s.peer.uncertain = true
	return events
}

func (d *HTTPDecoder) httpTunnel(peer *httpConnection) {
	for _, s := range peer.streams {
		s.clearFraming()
		s.resync, s.anchored = true, false
	}
}

func (d *HTTPDecoder) httpReanchor(st *flow.State, s *httpStream, v dpi.StreamView, res *dpi.StreamResult) {
	rejected := s.body != nil && s.body.rejected
	if !v.HasPacketStart || v.PacketStart < 0 || v.PacketStart >= len(v.Bytes) ||
		s.h2 != nil || s.declaredBody() && !rejected {
		return
	}
	response, valid := httpStart(v.Bytes[v.PacketStart:])
	if !valid || s.role != dpi.DirUnknown && response != (s.role == dpi.ServerToClient) {
		return
	}
	// Finishing a split start line takes precedence over interpreting its tail
	// as a new (possibly extension-method) start line.
	if v.PacketStart > 0 && s.lineStart == 0 && !response {
		if _, complete := httpStart(v.Bytes); complete &&
			(!httpCommonRequest(v.Bytes[v.PacketStart:]) || httpCommonRequest(v.Bytes)) {
			return
		}
	}
	recovering := s.resync || s.untilClose || v.PacketStart > 0 || rejected
	// With no transport authority a body-free request is also a role probe.
	// An earlier request-looking injection on the opposite endpoint must not
	// permanently veto the real client's next packet. A contradictory body
	// declaration is not allowed to establish framing for that endpoint.
	if !recovering && s.role == dpi.DirUnknown && !response && !s.peer.acceptsStart(s.key, false) {
		candidate := v.Bytes[v.PacketStart:]
		_, headers := parseHTTP(candidate)
		_, length := headers["content-length"]
		_, coding := headers["transfer-encoding"]
		recovering = bytes.Contains(candidate, []byte("\n\n")) || bytes.Contains(candidate, []byte("\r\n\r\n"))
		recovering = recovering && (!length || headers["content-length"] == "0") && !coding
	}
	if !recovering {
		return
	}
	// A packet-boundary guess cannot drain a FIFO or authorize a tunnel.
	// Exact correlation can still be used at boundaries we actually followed.
	if !rejected {
		s.peer.uncertain = true
	}
	if s.role == dpi.DirUnknown && !s.peer.acceptsStart(s.key, response) {
		s.peer.methods, s.peer.dropped = nil, 0
		s.peer.clientKnown, s.peer.serverKnown = false, false
		if response {
			s.peer.server, s.peer.serverKnown = s.key, true
		} else {
			s.peer.client, s.peer.clientKnown = s.key, true
		}
	}
	var events []dpi.Event
	if v.PacketStart > 0 && s.anchored && !s.untilClose && !rejected {
		events = []dpi.Event{{FlowID: st.ID(), Proto: "http", Kind: "malformed",
			Attributes: map[string]any{"error": "incomplete HTTP headers before packet-boundary re-anchor"}}}
	}
	metadataFrame(res, v, v.PacketStart, events)
	s.clearFraming()
	s.resync, s.anchored = false, false
	s.suppressMalformed = true
}
