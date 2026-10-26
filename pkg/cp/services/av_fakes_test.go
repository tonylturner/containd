// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeClamdReply returns the raw bytes written back for one command. INSTREAM
// receives the reassembled stream; other commands receive nil.
type fakeClamdReply func(cmd string, stream []byte) []byte

// startFakeClamd serves the clamd NUL-delimited protocol on a Unix socket.
// It reads a complete INSTREAM before replying, as clamd does.
func startFakeClamd(t *testing.T, reply fakeClamdReply) string {
	t.Helper()
	// Unix socket paths are length-limited; t.TempDir can exceed it on macOS.
	dir, err := os.MkdirTemp("/tmp", "clamd-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "clamd.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen(unix): %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeClamd(conn, reply)
		}
	}()
	return socketPath
}

func serveFakeClamd(c net.Conn, reply fakeClamdReply) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	cmd, err := r.ReadString(0)
	if err != nil || !strings.HasPrefix(cmd, "z") {
		return
	}
	cmd = strings.TrimSuffix(strings.TrimPrefix(cmd, "z"), "\x00")
	var stream []byte
	if cmd == "INSTREAM" {
		for {
			var hdr [4]byte
			if _, err := io.ReadFull(r, hdr[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(hdr[:])
			if n == 0 {
				break
			}
			chunk := make([]byte, n)
			if _, err := io.ReadFull(r, chunk); err != nil {
				return
			}
			stream = append(stream, chunk...)
		}
	}
	out := reply(cmd, stream)
	if out != nil {
		_, _ = c.Write(out)
	}
}

// icapRequest is one strictly parsed ICAP request.
type icapRequest struct {
	Method       string
	URI          string
	Header       textproto.MIMEHeader
	Encapsulated string
	HTTPHeader   string
	Body         []byte
}

// startFakeICAP parses each request per RFC 3507 (Encapsulated offsets and a
// chunked, terminated body) and answers with respond. A request that violates
// the framing receives "ICAP/1.0 400 Bad Request". tlsCfg enables TLS.
func startFakeICAP(t *testing.T, tlsCfg *tls.Config, respond func(icapRequest) string) (string, <-chan icapRequest) {
	t.Helper()
	var (
		ln  net.Listener
		err error
	)
	if tlsCfg != nil {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	requests := make(chan icapRequest, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				req, err := readStrictICAPRequest(bufio.NewReader(c))
				if err != nil {
					_, _ = io.WriteString(c, "ICAP/1.0 400 Bad Request\r\nX-Error: "+strings.ReplaceAll(err.Error(), "\r\n", " ")+"\r\n\r\n")
					return
				}
				// Record only after the full request has been read.
				requests <- req
				_, _ = io.WriteString(c, respond(req))
			}(conn)
		}
	}()
	return ln.Addr().String(), requests
}

func readStrictICAPRequest(r *bufio.Reader) (icapRequest, error) {
	tp := textproto.NewReader(r)
	line, err := tp.ReadLine()
	if err != nil {
		return icapRequest{}, err
	}
	parts := strings.Fields(line)
	if len(parts) != 3 || parts[2] != "ICAP/1.0" {
		return icapRequest{}, fmt.Errorf("bad request line %q", line)
	}
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		return icapRequest{}, err
	}
	req := icapRequest{Method: parts[0], URI: parts[1], Header: hdr, Encapsulated: hdr.Get("Encapsulated")}
	if hdr.Get("Host") == "" {
		return icapRequest{}, fmt.Errorf("missing Host")
	}
	if req.Encapsulated == "" {
		return icapRequest{}, fmt.Errorf("missing Encapsulated")
	}
	offsets := map[string]int{}
	var order []string
	for _, field := range strings.Split(req.Encapsulated, ",") {
		name, val, ok := strings.Cut(strings.TrimSpace(field), "=")
		n, err := strconv.Atoi(val)
		if !ok || err != nil || n < 0 {
			return icapRequest{}, fmt.Errorf("bad Encapsulated %q", req.Encapsulated)
		}
		offsets[name] = n
		order = append(order, name)
	}
	last := order[len(order)-1]
	if last != "null-body" && last != "res-body" && last != "req-body" && last != "opt-body" {
		return icapRequest{}, fmt.Errorf("Encapsulated must end with a body entity: %q", req.Encapsulated)
	}
	if resHdr, ok := offsets["res-hdr"]; ok {
		if resHdr != 0 {
			return icapRequest{}, fmt.Errorf("res-hdr offset %d", resHdr)
		}
		hdrLen := offsets[last]
		buf := make([]byte, hdrLen)
		if _, err := io.ReadFull(r, buf); err != nil {
			return icapRequest{}, fmt.Errorf("short encapsulated header: %w", err)
		}
		req.HTTPHeader = string(buf)
		if !strings.HasSuffix(req.HTTPHeader, "\r\n\r\n") || strings.Count(req.HTTPHeader, "\r\n\r\n") != 1 {
			return icapRequest{}, fmt.Errorf("res-body offset does not end the HTTP header: %q", req.HTTPHeader)
		}
	}
	if last == "res-body" {
		body, err := readChunked(r)
		if err != nil {
			return icapRequest{}, err
		}
		req.Body = body
		if want := fmt.Sprintf("Content-Length: %d\r\n", len(body)); !strings.Contains(req.HTTPHeader, want) {
			return icapRequest{}, fmt.Errorf("encapsulated Content-Length does not match %d-byte body", len(body))
		}
	}
	return req, nil
}

func readChunked(r *bufio.Reader) ([]byte, error) {
	var body []byte
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("chunk size: %w", err)
		}
		size, err := strconv.ParseInt(strings.TrimSpace(strings.SplitN(line, ";", 2)[0]), 16, 64)
		if err != nil || size < 0 {
			return nil, fmt.Errorf("bad chunk size %q", line)
		}
		if size == 0 {
			if crlf, err := r.ReadString('\n'); err != nil || crlf != "\r\n" {
				return nil, fmt.Errorf("missing final CRLF after terminator")
			}
			return body, nil
		}
		chunk := make([]byte, size)
		if _, err := io.ReadFull(r, chunk); err != nil {
			return nil, fmt.Errorf("short chunk: %w", err)
		}
		body = append(body, chunk...)
		var crlf [2]byte
		if _, err := io.ReadFull(r, crlf[:]); err != nil || !bytes.Equal(crlf[:], []byte("\r\n")) {
			return nil, fmt.Errorf("chunk not terminated by CRLF")
		}
	}
}

// testCA issues server certificates for TLS tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	PEM  []byte
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca *testCA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}

// serverConfig returns a TLS server config with a leaf for dnsNames.
func (ca *testCA) serverConfig(t *testing.T, dnsNames ...string) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
}
