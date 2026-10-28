// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
	"github.com/tonylturner/containd/pkg/cp/config"
)

const (
	defaultICAPService = "avscan"
	// icapMaxHeaderBytes bounds the ICAP status line and headers of a reply.
	icapMaxHeaderBytes = 64 << 10
	// icapChunkSize is the chunk size an object body is streamed in.
	icapChunkSize = 64 << 10
	icapREQMOD    = "REQMOD"
	icapRESPMOD   = "RESPMOD"
)

// ICAPClient is a generic RFC 3507 client: OPTIONS probes, REQMOD for
// uploads and RESPMOD for downloads. It sends no Preview, so the server
// answers only once it holds the complete object, and it never accepts
// adapted content: a reply is a verdict or an error.
type ICAPClient struct {
	// Timeout bounds connecting. A scan is bounded by the caller's ctx
	// deadline when there is one and by Timeout otherwise; a probe is
	// bounded by whichever of the two ends first.
	Timeout time.Duration
	// RootCAs verifies TLS servers. Nil uses the system roots.
	RootCAs *x509.CertPool
}

// ICAPVerdict is the parsed scan outcome.
type ICAPVerdict struct {
	Verdict   string // clean or malware
	Signature string // threat name when the server named one
}

type icapTarget struct {
	addr    string
	host    string
	service string
}

func parseICAPTarget(srv config.ICAPServer) (icapTarget, error) {
	addr := strings.TrimSpace(srv.Address)
	if addr == "" {
		return icapTarget{}, errors.New("icap address empty")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return icapTarget{}, fmt.Errorf("icap address %q: %w", addr, err)
	}
	if host == "" || port == "" {
		return icapTarget{}, fmt.Errorf("icap address %q must be host:port", addr)
	}
	service := strings.TrimSpace(srv.Service)
	if service == "" {
		service = defaultICAPService
	}
	if strings.ContainsFunc(service, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return icapTarget{}, fmt.Errorf("icap service %q contains whitespace or control characters", service)
	}
	return icapTarget{addr: addr, host: host, service: strings.TrimPrefix(service, "/")}, nil
}

func (t icapTarget) uri() string {
	return "icap://" + t.addr + "/" + t.service
}

func (c *ICAPClient) timeout() time.Duration {
	if c.Timeout <= 0 {
		return DefaultAVTimeout
	}
	return c.Timeout
}

// scanDeadline is the caller's deadline when it set one, else Timeout.
func (c *ICAPClient) scanDeadline(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(c.timeout())
}

// probeDeadline is the sooner of the caller's deadline and Timeout.
func (c *ICAPClient) probeDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(c.timeout())
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	return deadline
}

// dial connects with plaintext TCP or, when useTLS is set, verified TLS 1.2+
// whose server name is the configured host. There is no plaintext fallback.
// Connecting is bounded by Timeout; the connection is bounded by deadline
// and closed when ctx ends. The returned stop func releases that watch.
func (c *ICAPClient) dial(ctx context.Context, srv config.ICAPServer, t icapTarget, deadline time.Time) (net.Conn, func() bool, error) {
	netDialer := &net.Dialer{Timeout: c.timeout()}
	var (
		conn net.Conn
		err  error
	)
	if srv.UseTLS {
		dialer := &tls.Dialer{NetDialer: netDialer, Config: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: t.host,
			RootCAs:    c.RootCAs,
		}}
		conn, err = dialer.DialContext(ctx, "tcp", t.addr)
	} else {
		conn, err = netDialer.DialContext(ctx, "tcp", t.addr)
	}
	if err != nil {
		return nil, nil, err
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	return conn, stop, nil
}

// Probe sends OPTIONS and requires a 200 reply that, when it lists Methods,
// includes every method in required (REQMOD, RESPMOD).
func (c *ICAPClient) Probe(ctx context.Context, srv config.ICAPServer, required ...string) error {
	if c == nil {
		return errors.New("icap client nil")
	}
	t, err := parseICAPTarget(srv)
	if err != nil {
		return err
	}
	conn, stop, err := c.dial(ctx, srv, t, c.probeDeadline(ctx))
	if err != nil {
		return err
	}
	defer stop()
	defer conn.Close()
	req := "OPTIONS " + t.uri() + " ICAP/1.0\r\nHost: " + t.addr + "\r\nEncapsulated: null-body=0\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return err
	}
	code, hdr, err := readICAPResponse(conn)
	if err != nil {
		return fmt.Errorf("icap options: %w", err)
	}
	if code != 200 {
		return fmt.Errorf("icap options: unexpected status %d", code)
	}
	methods := hdr.Get("Methods")
	if methods == "" {
		return nil
	}
	for _, m := range required {
		if !listsMethod(methods, m) {
			return fmt.Errorf("icap service %q does not support %s (methods %q)", t.service, m, methods)
		}
	}
	return nil
}

func listsMethod(methods, want string) bool {
	for _, m := range strings.Split(methods, ",") {
		if strings.EqualFold(strings.TrimSpace(m), want) {
			return true
		}
	}
	return false
}

// Scan streams obj to the server: an upload as REQMOD with its request
// head, a download as RESPMOD with its request and response heads. The
// reply is malware when it carries an infection header, clean only on a
// 204 without one, and an error otherwise; a reply is never clean for a
// body the server did not receive in full.
func (c *ICAPClient) Scan(ctx context.Context, srv config.ICAPServer, obj avscan.Object) (ICAPVerdict, error) {
	if c == nil {
		return ICAPVerdict{}, errors.New("icap client nil")
	}
	t, err := parseICAPTarget(srv)
	if err != nil {
		return ICAPVerdict{}, err
	}
	req, err := encapsulate(t, obj)
	if err != nil {
		return ICAPVerdict{}, err
	}
	conn, stop, err := c.dial(ctx, srv, t, c.scanDeadline(ctx))
	if err != nil {
		return ICAPVerdict{}, err
	}
	defer stop()
	defer conn.Close()
	werr := req.write(conn, io.NewSectionReader(obj.Body, 0, obj.Size), obj.Size)
	if errors.Is(werr, errObjectSource) {
		// The object itself is unreadable: no reply is awaited.
		return ICAPVerdict{}, fmt.Errorf("icap %s: %w", req.method, werr)
	}
	code, hdr, rerr := readICAPResponse(conn)
	var verdict ICAPVerdict
	if rerr == nil {
		verdict, rerr = icapVerdict(code, hdr)
	}
	switch {
	case rerr == nil && verdict.Verdict == "malware":
		// A detection stands even when the server stopped reading early.
		return verdict, nil
	case werr != nil:
		return ICAPVerdict{}, fmt.Errorf("icap %s: %w", req.method, werr)
	case rerr != nil:
		return ICAPVerdict{}, fmt.Errorf("icap %s: %w", req.method, rerr)
	}
	return verdict, nil
}

// icapMessage is one composed REQMOD or RESPMOD request.
type icapMessage struct {
	method string
	// head is the ICAP request line and headers through the blank line.
	head string
	// entities are the encapsulated HTTP heads in Encapsulated order.
	entities [][]byte
}

// encapsulate composes the request for obj. The encapsulated head that owns
// the body is rewritten to describe the body as sent; a RESPMOD request head
// describes the request only and is sent as held.
func encapsulate(t icapTarget, obj avscan.Object) (icapMessage, error) {
	var (
		req      icapMessage
		sections []string
	)
	switch obj.Direction {
	case avscan.Upload:
		if len(obj.RequestHead) == 0 {
			return req, errors.New("upload object without request head")
		}
		head, err := describeBody(obj.RequestHead, obj.Size)
		if err != nil {
			return req, fmt.Errorf("request head: %w", err)
		}
		req.method = icapREQMOD
		req.entities = [][]byte{head}
		sections = []string{"req-hdr=0", "req-body=%d"}
	case avscan.Download:
		if len(obj.ResponseHead) == 0 {
			return req, errors.New("download object without response head")
		}
		head, err := describeBody(obj.ResponseHead, obj.Size)
		if err != nil {
			return req, fmt.Errorf("response head: %w", err)
		}
		req.method = icapRESPMOD
		if len(obj.RequestHead) > 0 {
			if err := validHead(obj.RequestHead); err != nil {
				return req, fmt.Errorf("request head: %w", err)
			}
			req.entities = [][]byte{obj.RequestHead, head}
			sections = []string{"req-hdr=0", "res-hdr=%d", "res-body=%d"}
		} else {
			req.entities = [][]byte{head}
			sections = []string{"res-hdr=0", "res-body=%d"}
		}
	default:
		return req, fmt.Errorf("object direction %q is not upload or download", obj.Direction)
	}
	if obj.Size == 0 {
		sections[len(sections)-1] = "null-body=%d"
	}
	offset := 0
	for i := 1; i < len(sections); i++ {
		offset += len(req.entities[i-1])
		sections[i] = fmt.Sprintf(sections[i], offset)
	}
	var b strings.Builder
	b.WriteString(req.method + " " + t.uri() + " ICAP/1.0\r\n")
	b.WriteString("Host: " + t.addr + "\r\n")
	b.WriteString("Allow: 204\r\n")
	if obj.Client.IsValid() {
		b.WriteString("X-Client-IP: " + ipText(obj.Client) + "\r\n")
	}
	if obj.Server.IsValid() {
		b.WriteString("X-Server-IP: " + ipText(obj.Server) + "\r\n")
	}
	b.WriteString("Encapsulated: " + strings.Join(sections, ", ") + "\r\n\r\n")
	req.head = b.String()
	return req, nil
}

func ipText(ap netip.AddrPort) string {
	return ap.Addr().Unmap().WithZone("").String()
}

// errObjectSource marks a body that could not be read from the object, as
// opposed to one the server would not take.
var errObjectSource = errors.New("object body unreadable")

// write sends the request with the body as chunks terminated by a
// zero-length chunk (RFC 3507 section 4.4). A body shorter than size is an
// errObjectSource: the request is left unterminated and the server never
// sees a complete object.
func (r icapMessage) write(w io.Writer, body io.Reader, size int64) error {
	bw := bufio.NewWriterSize(w, icapChunkSize+64)
	_, _ = bw.WriteString(r.head)
	for _, e := range r.entities {
		_, _ = bw.Write(e)
	}
	if size > 0 {
		buf := make([]byte, icapChunkSize)
		for remaining := size; remaining > 0; {
			n := int(min(int64(len(buf)), remaining))
			if _, err := io.ReadFull(body, buf[:n]); err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					return fmt.Errorf("%w: ended with %d of %d bytes outstanding", errObjectSource, remaining, size)
				}
				return fmt.Errorf("%w: %w", errObjectSource, err)
			}
			_, _ = bw.WriteString(strconv.FormatInt(int64(n), 16) + "\r\n")
			if _, err := bw.Write(buf[:n]); err != nil {
				return err
			}
			_, _ = bw.WriteString("\r\n")
			remaining -= int64(n)
		}
		_, _ = bw.WriteString("0\r\n\r\n")
	}
	return bw.Flush()
}

// describeBody returns head with its message framing replaced so that it
// describes the encapsulated body: Transfer-Encoding and Content-Length are
// removed and Content-Length is set to size when there is a body.
// Content-Encoding stays, because the body is sent as transferred.
func describeBody(head []byte, size int64) ([]byte, error) {
	lines, err := headLines(head)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.Grow(len(head) + 32)
	b.Write(lines[0])
	b.WriteString("\r\n")
	for _, line := range lines[1:] {
		name, _, _ := bytes.Cut(line, []byte(":"))
		name = bytes.TrimRight(name, " \t")
		if bytes.EqualFold(name, []byte("Transfer-Encoding")) || bytes.EqualFold(name, []byte("Content-Length")) {
			continue
		}
		b.Write(line)
		b.WriteString("\r\n")
	}
	if size > 0 {
		b.WriteString("Content-Length: " + strconv.FormatInt(size, 10) + "\r\n")
	}
	b.WriteString("\r\n")
	return b.Bytes(), nil
}

// validHead reports whether head is a complete HTTP/1.x head.
func validHead(head []byte) error {
	_, err := headLines(head)
	return err
}

// headLines splits a head into its start line and field lines. The head
// must be CRLF-delimited, end with the blank line and carry nothing after
// it; folded field lines are refused.
func headLines(head []byte) ([][]byte, error) {
	body := bytes.Index(head, []byte("\r\n\r\n"))
	if body < 0 || body+4 != len(head) {
		return nil, errors.New("head does not end with a blank line")
	}
	lines := bytes.Split(head[:body], []byte("\r\n"))
	if len(lines[0]) == 0 {
		return nil, errors.New("empty start line")
	}
	for _, line := range lines[1:] {
		if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
			return nil, errors.New("folded or empty header field")
		}
		if colon := bytes.IndexByte(line, ':'); colon <= 0 {
			return nil, errors.New("header field without a name")
		}
	}
	return lines, nil
}

// icapVerdict classifies a reply. An infection header is malware on any
// status; a 204 without one is clean; everything else is an error.
func icapVerdict(code int, hdr textproto.MIMEHeader) (ICAPVerdict, error) {
	if sig, found := icapInfection(hdr); found {
		return ICAPVerdict{Verdict: "malware", Signature: sig}, nil
	}
	switch code {
	case 204:
		return ICAPVerdict{Verdict: "clean"}, nil
	case 200:
		return ICAPVerdict{}, errors.New("server returned modified content without an infection header")
	default:
		return ICAPVerdict{}, fmt.Errorf("unexpected status %d", code)
	}
}

// icapInfection reports whether the reply declares an infection: an
// X-Infection-Found or X-Violations-Found header, the legacy X-Virus-ID, or
// an X-ICAP-Status containing "VirusFound". The threat name comes from the
// Threat parameter of X-Infection-Found, else from X-Virus-ID.
func icapInfection(hdr textproto.MIMEHeader) (string, bool) {
	found := false
	signature := ""
	if v := hdr.Get("X-Infection-Found"); v != "" {
		found = true
		for _, p := range strings.Split(v, ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(p), "=")
			if ok && strings.EqualFold(strings.TrimSpace(name), "Threat") {
				signature = strings.TrimSpace(value)
			}
		}
	}
	if v := strings.TrimSpace(hdr.Get("X-Virus-ID")); v != "" {
		found = true
		if signature == "" {
			signature = v
		}
	}
	if hdr.Get("X-Violations-Found") != "" || strings.Contains(strings.ToLower(hdr.Get("X-ICAP-Status")), "virusfound") {
		found = true
	}
	return signature, found
}

// readICAPResponse reads a bounded status line and header block. A read error
// or EOF before the blank line ending the headers is an error.
func readICAPResponse(r io.Reader) (int, textproto.MIMEHeader, error) {
	tp := textproto.NewReader(bufio.NewReader(io.LimitReader(r, icapMaxHeaderBytes)))
	line, err := tp.ReadLine()
	if err != nil {
		return 0, nil, fmt.Errorf("read status: %w", truncated(err))
	}
	proto, rest, ok := strings.Cut(line, " ")
	if !ok || proto != "ICAP/1.0" {
		return 0, nil, fmt.Errorf("malformed status line %q", line)
	}
	codeText, _, _ := strings.Cut(rest, " ")
	code, err := strconv.Atoi(codeText)
	if err != nil || code < 100 || code > 999 {
		return 0, nil, fmt.Errorf("malformed status line %q", line)
	}
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		return 0, nil, fmt.Errorf("read headers: %w", truncated(err))
	}
	return code, hdr, nil
}

func truncated(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errors.New("response truncated")
	}
	return err
}
