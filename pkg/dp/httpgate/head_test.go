// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"math"
	"os"
	"strings"
	"testing"
)

func TestParseRequestHead(t *testing.T) {
	for _, tc := range []struct {
		name   string
		raw    string
		body   bodyKind
		length int64
		detail string
	}{
		{"get", "GET /a HTTP/1.1\r\nHost: h\r\n\r\n", bodyNone, 0, ""},
		{"post-cl", "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 12\r\n\r\n", bodyLength, 12, ""},
		{"post-cl-zero", "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n", bodyNone, 0, ""},
		{"chunked-mixed-case", "POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: Chunked\r\n\r\n", bodyChunked, 0, ""},
		{"absolute-form", "GET http://h/a HTTP/1.1\r\nHost: h\r\n\r\n", bodyNone, 0, ""},
		{"absolute-form-case", "GET http://H:80/a HTTP/1.1\r\nHost: h:80\r\n\r\n", bodyNone, 0, ""},
		{"absolute-form-no-host", "GET http://h/a HTTP/1.1\r\n\r\n", bodyNone, 0, ""},
		{"bare-lf", "GET /a HTTP/1.1\nHost: h\n\n", 0, 0, "line without CRLF"},
		{"mixed-lf", "POST /a HTTP/1.1\r\nHost: h\r\nX: a\nContent-Length: 5\r\n\r\n", 0, 0, "line without CRLF"},
		{"lf-blank-line", "GET /a HTTP/1.1\r\nHost: h\r\n\n", 0, 0, "line without CRLF"},
		{"leading-crlf", "\r\nGET /a HTTP/1.1\r\nHost: h\r\n\r\n", 0, 0, "blank line before the start line"},
		{"bare-cr-value", "POST /a HTTP/1.1\r\nHost: h\r\nX: a\rContent-Length: 5\r\n\r\n", 0, 0, "control character in header field"},
		{"nul-value", "GET /a HTTP/1.1\r\nHost: h\r\nX: a\x00b\r\n\r\n", 0, 0, "control character in header field"},
		{"del-value", "GET /a HTTP/1.1\r\nHost: h\r\nX: a\x7fb\r\n\r\n", 0, 0, "control character in header field"},
		{"htab-value", "GET /a HTTP/1.1\r\nHost: h\r\nX: a\tb\r\n\r\n", bodyNone, 0, ""},
		{"ctl-target", "GET /a\x01b HTTP/1.1\r\nHost: h\r\n\r\n", 0, 0, "invalid request line"},
		{"http10-te", "POST /a HTTP/1.0\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n", 0, 0, "HTTP/1.0 with Transfer-Encoding"},
		{"dup-host", "GET /a HTTP/1.1\r\nHost: h\r\nHost: h\r\n\r\n", 0, 0, "duplicate Host"},
		{"authority-mismatch", "GET http://real.test/a HTTP/1.1\r\nHost: logged.test\r\n\r\n", 0, 0, "absolute-form authority differs from Host"},
		{"http2", "PRI * HTTP/2.0\r\n\r\n", 0, 0, "not HTTP/1.x"},
		{"http09", "GET /a\r\n\r\n", 0, 0, "invalid request line"},
		{"connect", "CONNECT h:443 HTTP/1.1\r\nHost: h\r\n\r\n", 0, 0, "CONNECT"},
		{"upgrade", "GET /a HTTP/1.1\r\nHost: h\r\nUpgrade: h2c\r\n\r\n", 0, 0, "Upgrade request"},
		{"connection-upgrade", "GET /a HTTP/1.1\r\nHost: h\r\nConnection: upgrade\r\n\r\n", 0, 0, "Upgrade request"},
		{"cl-te", "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n", 0, 0, "Content-Length with Transfer-Encoding"},
		{"dup-cl", "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n", 0, 0, "duplicate Content-Length"},
		{"list-cl", "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1, 1\r\n\r\n", 0, 0, "invalid Content-Length"},
		{"neg-cl", "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: -1\r\n\r\n", 0, 0, "invalid Content-Length"},
		{"huge-cl", "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 99999999999999999999\r\n\r\n", 0, 0, "invalid Content-Length"},
		{"gzip-te", "POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", 0, 0, "transfer coding other than chunked"},
		{"identity-te", "POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: identity\r\n\r\n", 0, 0, "transfer coding other than chunked"},
		{"obs-fold", "GET /a HTTP/1.1\r\nHost: h\r\nX: 1\r\n 2\r\n\r\n", 0, 0, "obsolete line folding"},
		{"conn-host", "GET /a HTTP/1.1\r\nHost: h\r\nConnection: close, Host\r\n\r\n", 0, 0, "Connection nominates a framing field"},
		{"conn-te", "GET /a HTTP/1.1\r\nHost: h\r\nConnection: Transfer-Encoding\r\n\r\n", 0, 0, "Connection nominates a framing field"},
		{"trailer", "GET /a HTTP/1.1\r\nHost: h\r\nTrailer: X\r\n\r\n", 0, 0, "trailers declared"},
		{"te-trailers", "GET /a HTTP/1.1\r\nHost: h\r\nTE: trailers\r\n\r\n", 0, 0, "trailers declared"},
		{"bad-name", "GET /a HTTP/1.1\r\nHost: h\r\nBad Name: x\r\n\r\n", 0, 0, "invalid header field"},
		{"no-colon", "GET /a HTTP/1.1\r\nHost: h\r\nnocolon\r\n\r\n", 0, 0, "invalid header field"},
		{"spaces", "GET  /a HTTP/1.1\r\nHost: h\r\n\r\n", 0, 0, "invalid request line"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := parseRequestHead([]byte(tc.raw))
			if tc.detail != "" {
				var ue *unsupportedError
				if !errors.As(err, &ue) || ue.detail != tc.detail {
					t.Fatalf("err %v, want unsupported %q", err, tc.detail)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if h.body != tc.body || h.length != tc.length {
				t.Fatalf("body %d length %d", h.body, h.length)
			}
		})
	}
}

func TestParseResponseHead(t *testing.T) {
	for _, tc := range []struct {
		name   string
		raw    string
		method string
		body   bodyKind
		status int
		detail string
	}{
		{"cl", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", "GET", bodyLength, 200, ""},
		{"chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "GET", bodyChunked, 200, ""},
		{"until-close", "HTTP/1.1 200 OK\r\n\r\n", "GET", bodyUntilClose, 200, ""},
		{"no-reason", "HTTP/1.1 200\r\n\r\n", "GET", bodyUntilClose, 200, ""},
		{"head", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", "HEAD", bodyNone, 200, ""},
		{"204", "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n", "GET", bodyNone, 204, ""},
		{"304", "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n", "GET", bodyNone, 304, ""},
		{"100", "HTTP/1.1 100 Continue\r\n\r\n", "POST", bodyNone, 100, ""},
		{"http10", "HTTP/1.0 200 OK\r\n\r\n", "GET", bodyUntilClose, 200, ""},
		{"101", "HTTP/1.1 101 Switching Protocols\r\n\r\n", "GET", 0, 0, "101 without a client Upgrade"},
		{"cl-te", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n", "GET", 0, 0, "Content-Length with Transfer-Encoding"},
		{"bad-status", "HTTP/1.1 2000 OK\r\n\r\n", "GET", 0, 0, "invalid status line"},
		{"alpha-status", "HTTP/1.1 2x0 OK\r\n\r\n", "GET", 0, 0, "invalid status code"},
		{"not-http", "SSH-2.0-x\r\n\r\n", "GET", 0, 0, "invalid status line"},
		{"h2", "HTTP/2 200\r\n\r\n", "GET", 0, 0, "not HTTP/1.x"},
		{"bare-lf", "HTTP/1.1 200 OK\nContent-Length: 5\n\n", "GET", 0, 0, "line without CRLF"},
		{"mixed-lf", "HTTP/1.1 200 OK\r\nX: a\nContent-Length: 5\r\n\r\n", "GET", 0, 0, "line without CRLF"},
		{"leading-crlf", "\r\nHTTP/1.1 200 OK\r\n\r\n", "GET", 0, 0, "blank line before the start line"},
		{"ctl-reason", "HTTP/1.1 200 O\x00K\r\n\r\n", "GET", 0, 0, "invalid status line"},
		{"bare-cr-value", "HTTP/1.1 200 OK\r\nX: a\rContent-Length: 5\r\n\r\n", "GET", 0, 0, "control character in header field"},
		{"http10-te", "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "GET", 0, 0, "HTTP/1.0 with Transfer-Encoding"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := parseResponseHead([]byte(tc.raw), tc.method)
			if tc.detail != "" {
				var ue *unsupportedError
				if !errors.As(err, &ue) || ue.detail != tc.detail {
					t.Fatalf("err %v, want unsupported %q", err, tc.detail)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if h.body != tc.body || h.status != tc.status {
				t.Fatalf("body %d status %d", h.body, h.status)
			}
		})
	}
}

func TestEffectiveHost(t *testing.T) {
	for raw, want := range map[string]string{
		"GET /a HTTP/1.1\r\nHost: h.test\r\n\r\n":                    "h.test",
		"GET http://real.test/a HTTP/1.1\r\nHost: REAL.test\r\n\r\n": "real.test",
		"GET https://real.test:8443/a?q HTTP/1.1\r\n\r\n":            "real.test:8443",
		"OPTIONS * HTTP/1.1\r\nHost: h.test\r\n\r\n":                 "h.test",
	} {
		h, err := parseRequestHead([]byte(raw))
		if err != nil || h.host != want {
			t.Errorf("%q: host %q err %v, want %q", raw, h.host, err, want)
		}
	}
}

func TestHeadWithoutField(t *testing.T) {
	raw := "POST /a HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 3\r\nexpect: x\r\n\r\n"
	h, err := parseRequestHead([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	got := string(h.without("Expect"))
	if got != "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\n" {
		t.Fatalf("without: %q", got)
	}
	if string(h.raw) != raw {
		t.Fatal("raw head modified")
	}
}

func TestReadHeadCapAndRaw(t *testing.T) {
	raw := "GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b"
	br := bufio.NewReaderSize(strings.NewReader(raw), headCap)
	got, err := readHead(br)
	if err != nil || string(got) != raw[:len(raw)-len("GET /b")] || br.Buffered() != len("GET /b") {
		t.Fatalf("got %q err %v buffered %d", got, err, br.Buffered())
	}
	long := "GET /a HTTP/1.1\r\nX: " + strings.Repeat("a", headCap) + "\r\n\r\n"
	got, err = readHead(bufio.NewReaderSize(strings.NewReader(long), headCap))
	if !errors.Is(err, errHeadTooLarge) || !strings.HasPrefix(long, string(got)) {
		t.Fatalf("long line: err %v, raw prefix ok=%v", err, strings.HasPrefix(long, string(got)))
	}
	many := "GET /a HTTP/1.1\r\n" + strings.Repeat("X: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n", 2000) + "\r\n"
	if _, err = readHead(bufio.NewReaderSize(strings.NewReader(many), headCap)); !errors.Is(err, errHeadTooLarge) {
		t.Fatalf("many lines: err %v", err)
	}
	if _, err = readHead(bufio.NewReaderSize(strings.NewReader(""), headCap)); !errors.Is(err, io.EOF) {
		t.Fatalf("empty: %v", err)
	}
	if _, err = readHead(bufio.NewReaderSize(strings.NewReader("GET /a HTTP/1.1\r\n"), headCap)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("partial: %v", err)
	}
}

func TestChunkedReader(t *testing.T) {
	for _, tc := range []struct {
		name  string
		in    string
		want  string
		fails string
	}{
		{"two-chunks", "3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n", "abcde", ""},
		{"extension", "3;name=v\r\nabc\r\n0\r\n\r\n", "abc", ""},
		{"uppercase-hex", "A\r\n0123456789\r\n0\r\n\r\n", "0123456789", ""},
		{"bad-size", "zz\r\nabc\r\n0\r\n\r\n", "", "invalid chunk size"},
		{"empty-size", "\r\nabc\r\n", "", "invalid chunk size"},
		{"too-many-digits", "0000000000000001\r\na\r\n0\r\n\r\n", "", "invalid chunk size"},
		{"signed", "+3\r\nabc\r\n0\r\n\r\n", "", "invalid chunk size"},
		{"missing-crlf", "3\r\nabcX\r\n0\r\n\r\n", "", "missing CRLF after chunk data"},
		{"bare-lf-size", "3\nabc\r\n0\r\n\r\n", "", "chunk-size line without CRLF"},
		{"trailer", "3\r\nabc\r\n0\r\nX: 1\r\n\r\n", "", "trailers present"},
		{"early-eof-data", "5\r\nab", "", "early EOF inside chunk"},
		{"early-eof-size", "3\r\nabc\r\n", "", "early EOF reading chunk size"},
		{"long-size-line", strings.Repeat("0", chunkLineCap+1) + "3\r\nabc\r\n0\r\n\r\n", "", "chunk-size line over 4 KiB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &chunkedReader{r: bufio.NewReaderSize(strings.NewReader(tc.in), headCap)}
			got, err := io.ReadAll(r)
			if tc.fails != "" {
				var fe *framingError
				if !errors.As(err, &fe) || fe.detail != tc.fails {
					t.Fatalf("err %v, want framing %q", err, tc.fails)
				}
				return
			}
			if err != nil || string(got) != tc.want {
				t.Fatalf("got %q err %v", got, err)
			}
		})
	}
}

func TestLengthReaderEarlyEOF(t *testing.T) {
	r := &lengthReader{r: bufio.NewReader(strings.NewReader("abc")), n: 5}
	got, err := io.ReadAll(r)
	var fe *framingError
	if string(got) != "abc" || !errors.As(err, &fe) {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestChunkWriterRoundTrip(t *testing.T) {
	var out bytes.Buffer
	w := newBodyWriter(&out, bodyChunked)
	for _, p := range [][]byte{[]byte("hello"), nil, bytes.Repeat([]byte("x"), 300)} {
		if _, err := w.Write(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.finish(); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out.Bytes(), []byte("5\r\nhello\r\n12c\r\n")) || !bytes.HasSuffix(out.Bytes(), []byte("\r\n0\r\n\r\n")) {
		t.Fatalf("chunked output %q", out.Bytes())
	}
	got, err := io.ReadAll(&chunkedReader{r: bufio.NewReader(&out)})
	if err != nil || string(got) != "hello"+strings.Repeat("x", 300) {
		t.Fatalf("round trip %q %v", got, err)
	}
}

func TestSpoolMemoryThenUnlinkedFile(t *testing.T) {
	dir := t.TempDir()
	sp := newSpool(dir, 10)
	defer sp.close()
	if _, err := sp.Write([]byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	if sp.file != nil || cap(sp.mem) > 10 {
		t.Fatalf("10 bytes should stay in memory within the threshold (cap %d)", cap(sp.mem))
	}
	if _, err := sp.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if sp.file == nil || sp.mem != nil {
		t.Fatal("exceeding the threshold should move the body to a file")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("spool file visible in the directory while open: %v", entries)
	}
	got, err := io.ReadAll(sp.reader())
	if err != nil || string(got) != "0123456789abc" || sp.size != 13 {
		t.Fatalf("read back %q %v size %d", got, err, sp.size)
	}
	if sp.sum() != sha256hex([]byte("0123456789abc")) {
		t.Fatal("hash mismatch")
	}
	buf := make([]byte, 4)
	if n, err := sp.ReadAt(buf, 11); n != 2 || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt past end: n=%d err=%v", n, err)
	}
}

func TestSpoolFillOutcomes(t *testing.T) {
	sp := newSpool(t.TempDir(), 1<<20)
	src := bytes.NewReader([]byte("0123456789"))
	outcome, excess, err := sp.fill(src, 4)
	if outcome != fillOversized || err != nil || sp.size != 4 || string(excess) != "4" {
		t.Fatalf("oversized: %d %q %v size %d", outcome, excess, err, sp.size)
	}
	if rest, _ := io.ReadAll(src); string(rest) != "56789" {
		t.Fatalf("remainder %q left in the reader", rest)
	}
	sp = newSpool(t.TempDir(), 1<<20)
	outcome, excess, err = sp.fill(bytes.NewReader([]byte("0123")), 4)
	if outcome != fillComplete || err != nil || len(excess) != 0 || sp.size != 4 {
		t.Fatalf("exact: %d %q %v", outcome, excess, err)
	}
	sp = newSpool(t.TempDir(), 1<<20)
	outcome, excess, err = sp.fill(bytes.NewReader([]byte("0123")), math.MaxInt64)
	if outcome != fillComplete || err != nil || len(excess) != 0 || sp.size != 4 {
		t.Fatalf("MaxInt64 cap: %d %q %v", outcome, excess, err)
	}
	sp = newSpool("/nonexistent/httpgate-spool", 2)
	outcome, excess, err = sp.fill(bytes.NewReader([]byte("0123")), 10)
	var se *spoolError
	if outcome != fillDisk || !errors.As(err, &se) || string(excess) != "0123" {
		t.Fatalf("disk: %d %q %v", outcome, excess, err)
	}
	sp = newSpool(t.TempDir(), 1<<20)
	outcome, _, err = sp.fill(&lengthReader{r: bufio.NewReader(strings.NewReader("ab")), n: 4}, 10)
	var fe *framingError
	if outcome != fillFraming || !errors.As(err, &fe) {
		t.Fatalf("framing: %d %v", outcome, err)
	}
}
