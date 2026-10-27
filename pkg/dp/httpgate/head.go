// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// bodyKind is the message body framing.
type bodyKind int

const (
	bodyNone bodyKind = iota
	bodyLength
	bodyChunked
	bodyUntilClose
)

// unsupportedError marks a head the gate refuses to interpret. The raw
// bytes stay intact for a policy-dependent splice.
type unsupportedError struct{ detail string }

func (e *unsupportedError) Error() string { return "httpgate: unsupported: " + e.detail }

func unsupported(format string, args ...any) error {
	return &unsupportedError{fmt.Sprintf(format, args...)}
}

// headerField is one header line; start and end delimit it in raw.
type headerField struct {
	name, value string
	start, end  int
}

// head is one parsed request or response head.
type head struct {
	raw     []byte
	request bool
	method  string
	target  string
	status  int
	http10  bool
	fields  []headerField

	body      bodyKind
	length    int64
	connClose bool
	keepAlive bool
	expect    string
	hasExpect bool
	host      string
}

// parseRequestHead interprets one request head strictly.
func parseRequestHead(raw []byte) (*head, error) {
	h := &head{raw: raw, request: true}
	return h, h.parse("")
}

// parseResponseHead interprets one response head; reqMethod decides
// whether a body follows.
func parseResponseHead(raw []byte, reqMethod string) (*head, error) {
	h := &head{raw: raw}
	return h, h.parse(reqMethod)
}

func (h *head) parse(reqMethod string) error {
	pos, err := h.parseStartLine()
	if err != nil {
		return err
	}
	if err := h.parseFields(pos); err != nil {
		return err
	}
	return h.interpret(reqMethod)
}

// parseStartLine returns the offset after the start line.
func (h *head) parseStartLine() (int, error) {
	pos := 0
	for {
		nl := bytes.IndexByte(h.raw[pos:], '\n')
		if nl < 0 {
			return 0, unsupported("incomplete head")
		}
		line := trimCR(h.raw[pos : pos+nl])
		pos += nl + 1
		if len(line) == 0 {
			continue
		}
		if h.request {
			return pos, h.parseRequestLine(string(line))
		}
		return pos, h.parseStatusLine(string(line))
	}
}

func (h *head) parseRequestLine(line string) error {
	parts := strings.Split(line, " ")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return unsupported("invalid request line")
	}
	if !isToken(parts[0]) {
		return unsupported("invalid method")
	}
	if err := h.setVersion(parts[2]); err != nil {
		return err
	}
	h.method, h.target = parts[0], parts[1]
	if h.method == "CONNECT" {
		return unsupported("CONNECT")
	}
	return nil
}

func (h *head) parseStatusLine(line string) error {
	version, rest, ok := strings.Cut(line, " ")
	if !ok {
		return unsupported("invalid status line")
	}
	if err := h.setVersion(version); err != nil {
		return err
	}
	if len(rest) < 3 || (len(rest) > 3 && rest[3] != ' ') {
		return unsupported("invalid status line")
	}
	code, err := strconv.Atoi(rest[:3])
	if err != nil || code < 100 || code > 999 || !isDigits(rest[:3]) {
		return unsupported("invalid status code")
	}
	h.status = code
	return nil
}

func (h *head) setVersion(v string) error {
	switch v {
	case "HTTP/1.1":
	case "HTTP/1.0":
		h.http10 = true
	default:
		return unsupported("not HTTP/1.x")
	}
	return nil
}

func (h *head) parseFields(pos int) error {
	for {
		nl := bytes.IndexByte(h.raw[pos:], '\n')
		if nl < 0 {
			return unsupported("incomplete head")
		}
		start, end := pos, pos+nl+1
		line := trimCR(h.raw[start : end-1])
		pos = end
		if len(line) == 0 {
			return nil
		}
		if line[0] == ' ' || line[0] == '\t' {
			return unsupported("obsolete line folding")
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || !isToken(string(line[:colon])) {
			return unsupported("invalid header field")
		}
		h.fields = append(h.fields, headerField{
			name:  string(line[:colon]),
			value: strings.Trim(string(line[colon+1:]), " \t"),
			start: start,
			end:   end,
		})
	}
}

// interpret derives framing and connection semantics from the fields.
func (h *head) interpret(reqMethod string) error {
	var (
		lengthSeen bool
		codings    []string
		upgrade    bool
		expects    []string
	)
	for _, f := range h.fields {
		switch strings.ToLower(f.name) {
		case "content-length":
			if lengthSeen {
				return unsupported("duplicate Content-Length")
			}
			n, err := parseContentLength(f.value)
			if err != nil {
				return err
			}
			lengthSeen, h.length = true, n
		case "transfer-encoding":
			for _, c := range strings.Split(f.value, ",") {
				codings = append(codings, strings.ToLower(strings.TrimSpace(c)))
			}
		case "connection":
			for _, t := range strings.Split(f.value, ",") {
				switch strings.ToLower(strings.TrimSpace(t)) {
				case "close":
					h.connClose = true
				case "keep-alive":
					h.keepAlive = true
				case "upgrade":
					upgrade = true
				case "content-length", "transfer-encoding", "host":
					return unsupported("Connection nominates a framing field")
				}
			}
		case "upgrade":
			upgrade = true
		case "trailer":
			return unsupported("trailers declared")
		case "te":
			if strings.Contains(strings.ToLower(f.value), "trailers") {
				return unsupported("trailers declared")
			}
		case "expect":
			expects = append(expects, strings.ToLower(f.value))
		case "host":
			h.host = f.value
		}
	}
	if len(codings) > 0 {
		if lengthSeen {
			return unsupported("Content-Length with Transfer-Encoding")
		}
		if len(codings) != 1 || codings[0] != "chunked" {
			return unsupported("transfer coding other than chunked")
		}
	}
	if len(expects) > 0 {
		h.hasExpect, h.expect = true, strings.Join(expects, ", ")
	}
	if h.request {
		if upgrade {
			return unsupported("Upgrade request")
		}
		switch {
		case len(codings) == 1:
			h.body = bodyChunked
		case lengthSeen && h.length > 0:
			h.body = bodyLength
		}
		return nil
	}
	if h.status == 101 {
		return unsupported("101 without a client Upgrade")
	}
	switch {
	case h.status < 200 || h.status == 204 || h.status == 304 || reqMethod == "HEAD":
		h.body = bodyNone
	case len(codings) == 1:
		h.body = bodyChunked
	case lengthSeen:
		if h.length > 0 {
			h.body = bodyLength
		}
	default:
		h.body = bodyUntilClose
	}
	return nil
}

// declaredLength is the Content-Length when the body is length-framed.
func (h *head) declaredLength() int64 {
	if h.body == bodyLength {
		return h.length
	}
	return 0
}

// without returns the raw head minus every field called name.
func (h *head) without(name string) []byte {
	out := make([]byte, 0, len(h.raw))
	pos := 0
	for _, f := range h.fields {
		if strings.EqualFold(f.name, name) {
			out = append(out, h.raw[pos:f.start]...)
			pos = f.end
		}
	}
	return append(out, h.raw[pos:]...)
}

// interim reports a 1xx response.
func (h *head) interim() bool { return !h.request && h.status < 200 }

func parseContentLength(v string) (int64, error) {
	if v == "" || len(v) > 19 || !isDigits(v) {
		return 0, unsupported("invalid Content-Length")
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, unsupported("invalid Content-Length")
	}
	return n, nil
}

func trimCR(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\r' {
		return b[:n-1]
	}
	return b
}

func isDigits(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// isToken reports an RFC 9110 token.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}
