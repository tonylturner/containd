// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

const (
	defaultICAPService = "avscan"
	// icapMaxHeaderBytes bounds the ICAP status line and headers of a reply.
	icapMaxHeaderBytes = 64 << 10
	// icapResponseHeader is the HTTP response header encapsulated in RESPMOD.
	icapResponseHeader = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n"
)

// ICAPClient is an RFC 3507 client for OPTIONS probes and RESPMOD scans. It
// does not negotiate previews: each scan sends the complete body it is given.
type ICAPClient struct {
	Timeout time.Duration
	// RootCAs verifies TLS servers. Nil uses the system roots.
	RootCAs *x509.CertPool
}

// ICAPVerdict is the parsed RESPMOD outcome.
type ICAPVerdict struct {
	Verdict string // clean or malware
	Status  string // X-ICAP-Status value when present
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

// dial connects with plaintext TCP or, when useTLS is set, verified TLS 1.2+
// whose server name is the configured host. There is no plaintext fallback.
func (c *ICAPClient) dial(ctx context.Context, srv config.ICAPServer, t icapTarget) (net.Conn, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultAVTimeout
	}
	netDialer := &net.Dialer{Timeout: timeout}
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
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// Probe sends OPTIONS and requires a 200 reply that, when it lists Methods,
// includes RESPMOD.
func (c *ICAPClient) Probe(ctx context.Context, srv config.ICAPServer) error {
	if c == nil {
		return errors.New("icap client nil")
	}
	t, err := parseICAPTarget(srv)
	if err != nil {
		return err
	}
	conn, err := c.dial(ctx, srv, t)
	if err != nil {
		return err
	}
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
	if methods := hdr.Get("Methods"); methods != "" && !strings.Contains(strings.ToUpper(methods), "RESPMOD") {
		return fmt.Errorf("icap service %q does not support RESPMOD (methods %q)", t.service, methods)
	}
	return nil
}

// Scan submits payload as the body of an encapsulated HTTP response.
// 204 means no modification and is clean. An X-ICAP-Status containing
// "virusfound" is malware. A 200 carrying an adapted response is reported as
// an error: no adapted-content contract is defined, so it is never clean.
func (c *ICAPClient) Scan(ctx context.Context, srv config.ICAPServer, payload []byte) (ICAPVerdict, error) {
	if c == nil {
		return ICAPVerdict{}, errors.New("icap client nil")
	}
	t, err := parseICAPTarget(srv)
	if err != nil {
		return ICAPVerdict{}, err
	}
	conn, err := c.dial(ctx, srv, t)
	if err != nil {
		return ICAPVerdict{}, err
	}
	defer conn.Close()
	if err := writeRESPMOD(conn, t, payload); err != nil {
		return ICAPVerdict{}, err
	}
	code, hdr, err := readICAPResponse(conn)
	if err != nil {
		return ICAPVerdict{}, fmt.Errorf("icap respmod: %w", err)
	}
	status := hdr.Get("X-ICAP-Status")
	if strings.Contains(strings.ToLower(status), "virusfound") {
		return ICAPVerdict{Verdict: "malware", Status: status}, nil
	}
	switch code {
	case 204:
		return ICAPVerdict{Verdict: "clean", Status: status}, nil
	case 200:
		return ICAPVerdict{}, errors.New("icap respmod: server returned modified content without a recognised verdict")
	default:
		return ICAPVerdict{}, fmt.Errorf("icap respmod: unexpected status %d", code)
	}
}

// writeRESPMOD writes the request with correct Encapsulated offsets and a
// chunked body terminated by a zero-length chunk (RFC 3507 section 4.4).
func writeRESPMOD(w io.Writer, t icapTarget, payload []byte) error {
	resHdr := fmt.Sprintf(icapResponseHeader, len(payload))
	encapsulated := fmt.Sprintf("res-hdr=0, res-body=%d", len(resHdr))
	if len(payload) == 0 {
		encapsulated = fmt.Sprintf("res-hdr=0, null-body=%d", len(resHdr))
	}
	bw := bufio.NewWriter(w)
	_, _ = bw.WriteString("RESPMOD " + t.uri() + " ICAP/1.0\r\n")
	_, _ = bw.WriteString("Host: " + t.addr + "\r\n")
	_, _ = bw.WriteString("Allow: 204\r\n")
	_, _ = bw.WriteString("Encapsulated: " + encapsulated + "\r\n\r\n")
	_, _ = bw.WriteString(resHdr)
	if len(payload) > 0 {
		_, _ = bw.WriteString(strconv.FormatInt(int64(len(payload)), 16) + "\r\n")
		_, _ = bw.Write(payload)
		_, _ = bw.WriteString("\r\n0\r\n\r\n")
	}
	return bw.Flush()
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
