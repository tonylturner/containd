// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// framingError reports a body whose framing broke after parsing started.
// The partial object is never delivered and the connection never spliced.
type framingError struct{ detail string }

func (e *framingError) Error() string { return "httpgate: framing: " + e.detail }

func framing(format string, args ...any) error {
	return &framingError{fmt.Sprintf(format, args...)}
}

// newBodyReader returns the decoded body of a message whose head is h,
// read from r. Read returns io.EOF when the body is complete and a
// framingError when it cannot be.
func newBodyReader(h *head, r *bufio.Reader) io.Reader {
	switch h.body {
	case bodyLength:
		return &lengthReader{r: r, n: h.length}
	case bodyChunked:
		return &chunkedReader{r: r}
	case bodyUntilClose:
		return &untilCloseReader{r: r}
	}
	return bytes.NewReader(nil)
}

// lengthReader reads exactly n bytes.
type lengthReader struct {
	r *bufio.Reader
	n int64
}

func (l *lengthReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	if errors.Is(err, io.EOF) {
		if l.n > 0 {
			return n, framing("early EOF with %d body bytes outstanding", l.n)
		}
		err = nil
	}
	return n, err
}

// chunkedReader decodes strict chunked transfer coding: CRLF delimiters,
// hexadecimal sizes of at most 15 digits, chunk-size lines under
// chunkLineCap, extensions ignored, trailers refused.
type chunkedReader struct {
	r         *bufio.Reader
	remain    int64
	afterData bool
	done      bool
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	for {
		if c.done {
			return 0, io.EOF
		}
		if c.remain == 0 {
			if err := c.nextChunk(); err != nil {
				return 0, err
			}
			continue
		}
		if int64(len(p)) > c.remain {
			p = p[:c.remain]
		}
		n, err := c.r.Read(p)
		c.remain -= int64(n)
		if errors.Is(err, io.EOF) {
			return n, framing("early EOF inside chunk")
		}
		return n, err
	}
}

func (c *chunkedReader) nextChunk() error {
	if c.afterData {
		if err := c.expectCRLF("after chunk data"); err != nil {
			return err
		}
	}
	line, err := c.r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > chunkLineCap {
		return framing("chunk-size line over 4 KiB")
	}
	if err != nil {
		return wrapRead(err, "reading chunk size")
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return framing("chunk-size line without CRLF")
	}
	size, err := parseChunkSize(line[:len(line)-2])
	if err != nil {
		return err
	}
	if size == 0 {
		if err := c.expectCRLF("after last chunk"); err != nil {
			return err
		}
		c.done = true
		return nil
	}
	c.remain, c.afterData = size, true
	return nil
}

// expectCRLF consumes a bare CRLF; anything else is a framing error, and
// after the last chunk it means a trailer is present.
func (c *chunkedReader) expectCRLF(where string) error {
	var crlf [2]byte
	if _, err := io.ReadFull(c.r, crlf[:]); err != nil {
		return wrapRead(err, where)
	}
	if crlf != [2]byte{'\r', '\n'} {
		if where == "after last chunk" {
			return framing("trailers present")
		}
		return framing("missing CRLF %s", where)
	}
	return nil
}

func parseChunkSize(line []byte) (int64, error) {
	if i := bytes.IndexByte(line, ';'); i >= 0 {
		line = line[:i]
	}
	line = bytes.TrimRight(line, " \t")
	if len(line) == 0 || len(line) > 15 || !isHex(line) {
		return 0, framing("invalid chunk size")
	}
	n, err := strconv.ParseInt(string(line), 16, 64)
	if err != nil {
		return 0, framing("invalid chunk size")
	}
	return n, nil
}

func isHex(b []byte) bool {
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// wrapRead turns an early EOF into a framing error and keeps timeouts and
// transport errors as they are.
func wrapRead(err error, where string) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return framing("early EOF %s", where)
	}
	return err
}

// untilCloseReader relays a close-delimited body; EOF completes it.
type untilCloseReader struct{ r *bufio.Reader }

func (u *untilCloseReader) Read(p []byte) (int, error) { return u.r.Read(p) }

// bodyWriter re-frames a decoded body for its recipient.
type bodyWriter interface {
	io.Writer
	// finish writes the framing terminator, if any.
	finish() error
}

// newBodyWriter frames body bytes as kind on w.
func newBodyWriter(w io.Writer, kind bodyKind) bodyWriter {
	if kind == bodyChunked {
		return &chunkWriter{w: w}
	}
	return plainWriter{w}
}

// plainWriter carries Content-Length and close-delimited bodies.
type plainWriter struct{ io.Writer }

func (plainWriter) finish() error { return nil }

// chunkWriter emits one extension-free chunk per Write.
type chunkWriter struct {
	w   io.Writer
	buf []byte
}

func (c *chunkWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.buf = append(c.buf[:0], strconv.FormatInt(int64(len(p)), 16)...)
	c.buf = append(c.buf, '\r', '\n')
	c.buf = append(c.buf, p...)
	c.buf = append(c.buf, '\r', '\n')
	if _, err := c.w.Write(c.buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *chunkWriter) finish() error {
	_, err := io.WriteString(c.w, "0\r\n\r\n")
	return err
}

// errStopped reports a copy ended by its stop channel.
var errStopped = errors.New("httpgate: forwarding stopped")

// copyBody streams src into dst until EOF, an error, or stop closes.
func copyBody(dst io.Writer, src io.Reader, stop <-chan struct{}) (int64, error) {
	buf := make([]byte, copyBufSize)
	var total int64
	for {
		select {
		case <-stop:
			return total, errStopped
		default:
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return total, nil
			}
			return total, rerr
		}
	}
}
