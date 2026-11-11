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
type httpStream struct {
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
	delete(d.streams, httpStreamKey{session, dir})
}

func (d *HTTPDecoder) ParseStream(st *flow.State, v dpi.StreamView) (dpi.StreamResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.streams == nil {
		d.streams = make(map[httpStreamKey]*httpStream)
	}
	key := httpStreamKey{v.Session, v.Dir}
	s := d.streams[key]
	if s == nil {
		s = &httpStream{}
		d.streams[key] = s
	}
	var res dpi.StreamResult
	for res.Consumed < len(v.Bytes) {
		off := res.Consumed
		p := v.Bytes[off:]
		n, events, err := d.httpFrame(st, s, p)
		if err != nil {
			return res, &dpi.FrameError{Offset: v.Base + int64(off), Reason: err.Error()}
		}
		if n == 0 {
			break
		}
		res.Consumed += n
		res.Frames = append(res.Frames, dpi.DecodedFrame{Start: v.Base + int64(off), End: v.Base + int64(res.Consumed), Events: events})
	}
	res.NeedMore = res.Consumed < len(v.Bytes)
	return res, nil
}

func (d *HTTPDecoder) httpFrame(st *flow.State, s *httpStream, p []byte) (int, []dpi.Event, error) {
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
		if bytes.HasPrefix(p, []byte("\r\n")) {
			s.trailers = false
			return 2, nil, nil
		}
		n := bytes.Index(p, []byte("\r\n\r\n"))
		if n < 0 {
			if len(p) > maxHTTPHeaders {
				return 0, nil, fmt.Errorf("HTTP trailer limit")
			}
			return 0, nil, nil
		}
		if n+4 > maxHTTPHeaders {
			return 0, nil, fmt.Errorf("HTTP trailer limit")
		}
		s.trailers = false
		return n + 4, nil, nil
	}
	if s.chunked {
		n := bytes.Index(p, []byte("\r\n"))
		if n < 0 {
			if len(p) > 1024 {
				return 0, nil, fmt.Errorf("HTTP chunk line limit")
			}
			return 0, nil, nil
		}
		if n > 1024 {
			return 0, nil, fmt.Errorf("HTTP chunk line limit")
		}
		size, err := strconv.ParseUint(strings.SplitN(string(p[:n]), ";", 2)[0], 16, 64)
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
		return n + 2, nil, nil
	}
	if p[0] == 'P' && bytes.HasPrefix([]byte(h2Preface), p[:min(len(p), len(h2Preface))]) {
		if len(p) < len(h2Preface) {
			return 0, nil, nil
		}
		s.h2 = newH2Stream()
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
			return s.h2.frame(st, p)
		}
	}
	end := bytes.Index(p, []byte("\r\n\r\n"))
	if end < 0 {
		if len(p) > maxHTTPHeaders {
			return 0, nil, fmt.Errorf("HTTP header limit")
		}
		return 0, nil, nil
	}
	end += 4
	if end > maxHTTPHeaders {
		return 0, nil, fmt.Errorf("HTTP header limit")
	}
	line, headers := parseHTTP(p[:end])
	if line == "" {
		return 0, nil, fmt.Errorf("invalid HTTP start line")
	}
	// Ambiguous framing is not a source of reliable metadata. Never treat
	// bytes inside an ambiguously delimited body as another request.
	if err := validateHTTPFraming(p[:end], headers); err != nil {
		return 0, nil, err
	}
	events := http1Events(st, &dpi.ParsedPacket{Payload: p[:end], Proto: "tcp", SrcPort: st.Key.SrcPort, DstPort: st.Key.DstPort})
	// A 101 switches this direction to binary frames; the client direction
	// independently recognizes its mandatory connection preface after the body.
	if strings.HasPrefix(line, "HTTP/") && strings.Contains(line, " 101 ") && strings.EqualFold(headers["upgrade"], "h2c") {
		s.h2 = newH2Stream()
	} else if parts := strings.Fields(line); strings.HasPrefix(line, "HTTP/") && len(parts) > 1 && (parts[1] == "204" || parts[1] == "304" || strings.HasPrefix(parts[1], "1")) {
		// These responses have no body even when Content-Length describes the
		// selected representation rather than bytes on this connection.
	} else if te := headers["transfer-encoding"]; te != "" {
		if !strings.EqualFold(te, "chunked") {
			return 0, nil, fmt.Errorf("unsupported HTTP transfer encoding")
		}
		s.chunked = true
	} else if cl, ok := headers["content-length"]; ok {
		n, err := strconv.ParseUint(cl, 10, 64)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid HTTP content length")
		}
		s.remaining = n
	} else if strings.HasPrefix(line, "HTTP/") {
		parts := strings.Fields(line)
		if len(parts) > 1 && parts[1] != "204" && parts[1] != "304" && !strings.HasPrefix(parts[1], "1") {
			s.untilClose = true
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
	lines := bytes.Split(raw, []byte("\r\n"))
	for _, line := range lines[1:] {
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
