// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func nulReply(s string) fakeClamdReply {
	return func(string, []byte) []byte { return []byte(s + "\x00") }
}

func TestClamdScanParsesNULReplies(t *testing.T) {
	cases := []struct {
		name    string
		reply   []byte
		verdict string
		sig     string
		errPart string
	}{
		{name: "clean", reply: []byte("stream: OK\x00"), verdict: "clean"},
		{name: "found", reply: []byte("stream: Win.Test.EICAR_HDB-1 FOUND\x00"), verdict: "malware", sig: "Win.Test.EICAR_HDB-1"},
		{name: "error", reply: []byte("INSTREAM size limit exceeded. ERROR\x00"), errPart: "size limit"},
		{name: "newline only", reply: []byte("stream: OK\n"), errPart: "truncated"},
		{name: "truncated", reply: []byte("stream: O"), errPart: "truncated"},
		{name: "empty close", reply: []byte{}, errPart: "truncated"},
		{name: "oversize", reply: bytes.Repeat([]byte("A"), clamdMaxReply+10), errPart: "size limit"},
		{name: "unknown", reply: []byte("stream: MAYBE\x00"), errPart: "unexpected reply"},
		{name: "found without name", reply: []byte("stream:  FOUND\x00"), errPart: "without signature"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sock := startFakeClamd(t, func(string, []byte) []byte { return tc.reply })
			res, err := (&ClamAVClient{Timeout: time.Second, Socket: sock}).Scan(context.Background(), strings.NewReader("payload"), 7)
			if tc.errPart != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errPart) {
					t.Fatalf("Scan() = %+v, %v; want error containing %q", res, err, tc.errPart)
				}
				return
			}
			if err != nil || res.Verdict != tc.verdict || res.Signature != tc.sig {
				t.Fatalf("Scan() = %+v, %v; want %s/%s", res, err, tc.verdict, tc.sig)
			}
		})
	}
}

func TestClamdScanStreamsChunkedPayload(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789abcdef"), (3*clamdChunkSize)/16+7)
	got := make(chan []byte, 1)
	sock := startFakeClamd(t, func(cmd string, stream []byte) []byte {
		if cmd == "INSTREAM" {
			got <- stream
		}
		return []byte("stream: OK\x00")
	})
	if _, err := (&ClamAVClient{Timeout: time.Second, Socket: sock}).Scan(context.Background(), bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if stream := <-got; !bytes.Equal(stream, payload) {
		t.Fatalf("clamd received %d bytes, want %d identical bytes", len(stream), len(payload))
	}
}

func TestClamdScanTimesOutWithoutReply(t *testing.T) {
	sock := startFakeClamd(t, func(string, []byte) []byte {
		time.Sleep(2 * time.Second)
		return nil
	})
	start := time.Now()
	_, err := (&ClamAVClient{Timeout: 200 * time.Millisecond, Socket: sock}).Scan(context.Background(), strings.NewReader("x"), 1)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("timeout not honoured: %s", elapsed)
	}
}

func TestClamdCommands(t *testing.T) {
	sock := startFakeClamd(t, func(cmd string, _ []byte) []byte {
		switch cmd {
		case "PING":
			return []byte("PONG\x00")
		case "VERSION":
			return []byte("ClamAV 1.5.2/27800/Mon Oct 26 08:00:00 2026\x00")
		case "RELOAD":
			return []byte("RELOADING\x00")
		}
		return []byte("UNKNOWN COMMAND\x00")
	})
	client := &ClamAVClient{Timeout: time.Second, Socket: sock}
	if err := client.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if v, err := client.Version(context.Background()); err != nil || !strings.HasPrefix(v, "ClamAV 1.5.2/27800/") {
		t.Fatalf("Version = %q, %v", v, err)
	}
	if err := client.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	bad := &ClamAVClient{Timeout: time.Second, Socket: startFakeClamd(t, nulReply("NOPE"))}
	if err := bad.Ping(context.Background()); err == nil {
		t.Fatal("Ping accepted a non-PONG reply")
	}
	if _, err := bad.Version(context.Background()); err == nil {
		t.Fatal("Version accepted a non-version reply")
	}
	if err := bad.Reload(context.Background()); err == nil {
		t.Fatal("Reload accepted a non-RELOADING reply")
	}
	if err := (&ClamAVClient{Timeout: time.Second}).Ping(context.Background()); err == nil {
		t.Fatal("Ping without socket succeeded")
	}
}

func icapReply(lines ...string) func(icapRequest) string {
	return func(icapRequest) string { return strings.Join(lines, "\r\n") + "\r\n\r\n" }
}

func TestICAPRespmodFramingAndVerdicts(t *testing.T) {
	payload := []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	cases := []struct {
		name    string
		reply   func(icapRequest) string
		verdict string
		errPart string
	}{
		{name: "204 clean", reply: icapReply("ICAP/1.0 204 No Content", "ISTag: \"t1\""), verdict: "clean"},
		{name: "virus header", reply: icapReply("ICAP/1.0 200 OK", "X-ICAP-Status: VirusFound", "Encapsulated: res-hdr=0, res-body=19"), verdict: "malware"},
		{name: "200 modified", reply: icapReply("ICAP/1.0 200 OK", "Encapsulated: res-hdr=0, res-body=19"), errPart: "modified content"},
		{name: "server error", reply: icapReply("ICAP/1.0 500 Server Error"), errPart: "unexpected status 500"},
		{name: "truncated headers", reply: func(icapRequest) string { return "ICAP/1.0 204 No Content\r\nISTag: x\r\n" }, errPart: "truncated"},
		{name: "truncated status", reply: func(icapRequest) string { return "ICAP/1.0 2" }, errPart: "status"},
		{name: "not icap", reply: icapReply("HTTP/1.1 200 OK"), errPart: "malformed status"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, reqs := startFakeICAP(t, nil, tc.reply)
			res, err := (&ICAPClient{Timeout: time.Second}).Scan(context.Background(), config.ICAPServer{Address: addr, Service: "avscan"}, payload)
			if tc.errPart != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errPart) {
					t.Fatalf("Scan() = %+v, %v; want error containing %q", res, err, tc.errPart)
				}
			} else if err != nil || res.Verdict != tc.verdict {
				t.Fatalf("Scan() = %+v, %v; want %s", res, err, tc.verdict)
			}
			select {
			case req := <-reqs:
				if req.Method != "RESPMOD" || req.URI != "icap://"+addr+"/avscan" || !bytes.Equal(req.Body, payload) {
					t.Fatalf("server saw %s %s body %q", req.Method, req.URI, req.Body)
				}
				if req.Header.Get("Allow") != "204" {
					t.Fatalf("Allow header = %q", req.Header.Get("Allow"))
				}
			case <-time.After(time.Second):
				t.Fatal("strict ICAP server rejected the request framing")
			}
		})
	}
}

func TestICAPRespmodEmptyBodyUsesNullBody(t *testing.T) {
	addr, reqs := startFakeICAP(t, nil, icapReply("ICAP/1.0 204 No Content"))
	if res, err := (&ICAPClient{Timeout: time.Second}).Scan(context.Background(), config.ICAPServer{Address: addr}, nil); err != nil || res.Verdict != "clean" {
		t.Fatalf("Scan(empty) = %+v, %v", res, err)
	}
	req := <-reqs
	if !strings.HasPrefix(req.Encapsulated, "res-hdr=0, null-body=") || len(req.Body) != 0 {
		t.Fatalf("Encapsulated = %q body %q", req.Encapsulated, req.Body)
	}
}

func TestICAPOptionsProbe(t *testing.T) {
	addr, reqs := startFakeICAP(t, nil, icapReply("ICAP/1.0 200 OK", "Methods: RESPMOD", "Encapsulated: null-body=0"))
	if err := (&ICAPClient{Timeout: time.Second}).Probe(context.Background(), config.ICAPServer{Address: addr, Service: "/scan"}); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	req := <-reqs
	if req.Method != "OPTIONS" || req.URI != "icap://"+addr+"/scan" || req.Encapsulated != "null-body=0" {
		t.Fatalf("OPTIONS request = %+v", req)
	}
	for name, reply := range map[string]func(icapRequest) string{
		"reqmod only": icapReply("ICAP/1.0 200 OK", "Methods: REQMOD", "Encapsulated: null-body=0"),
		"not found":   icapReply("ICAP/1.0 404 ICAP Service Not Found"),
		"truncated":   func(icapRequest) string { return "ICAP/1.0 200 OK\r\nMethods: RESPMOD\r\n" },
	} {
		t.Run(name, func(t *testing.T) {
			addr, _ := startFakeICAP(t, nil, reply)
			if err := (&ICAPClient{Timeout: time.Second}).Probe(context.Background(), config.ICAPServer{Address: addr}); err == nil {
				t.Fatal("Probe succeeded")
			}
		})
	}
}

func TestICAPRejectsUnsafeTargets(t *testing.T) {
	client := &ICAPClient{Timeout: time.Second}
	for _, srv := range []config.ICAPServer{
		{Address: ""},
		{Address: "no-port"},
		{Address: "127.0.0.1:1344", Service: "av\r\nX-Injected: 1"},
		{Address: "127.0.0.1:1344", Service: "a b"},
	} {
		if err := client.Probe(context.Background(), srv); err == nil {
			t.Fatalf("Probe(%+v) succeeded", srv)
		}
		if _, err := client.Scan(context.Background(), srv, []byte("x")); err == nil {
			t.Fatalf("Scan(%+v) succeeded", srv)
		}
	}
}

func TestICAPTLSVerifiesServerWithoutFallback(t *testing.T) {
	ca := newTestCA(t, "containd test ICAP CA")
	reply := func(req icapRequest) string {
		if req.Method == "OPTIONS" {
			return "ICAP/1.0 200 OK\r\nMethods: RESPMOD\r\nEncapsulated: null-body=0\r\n\r\n"
		}
		return "ICAP/1.0 204 No Content\r\n\r\n"
	}
	addr, reqs := startFakeICAP(t, ca.serverConfig(t, "localhost"), reply)
	_, port, _ := net.SplitHostPort(addr)
	named := config.ICAPServer{Address: net.JoinHostPort("localhost", port), UseTLS: true}

	trusted := &ICAPClient{Timeout: time.Second, RootCAs: ca.pool()}
	if err := trusted.Probe(context.Background(), named); err != nil {
		t.Fatalf("Probe over TLS: %v", err)
	}
	<-reqs
	if res, err := trusted.Scan(context.Background(), named, []byte("data")); err != nil || res.Verdict != "clean" {
		t.Fatalf("Scan over TLS = %+v, %v", res, err)
	}
	if req := <-reqs; string(req.Body) != "data" {
		t.Fatalf("TLS server saw body %q", req.Body)
	}

	// Without the private CA the system roots must reject the server.
	if err := (&ICAPClient{Timeout: time.Second}).Probe(context.Background(), named); err == nil {
		t.Fatal("Probe trusted an unknown CA")
	}
	// The server name comes from the configured host; the leaf only names localhost.
	byIP := config.ICAPServer{Address: addr, UseTLS: true}
	if err := trusted.Probe(context.Background(), byIP); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("Probe accepted a certificate for another name: %v", err)
	}
	// A plaintext server must fail instead of being used without TLS.
	plainAddr, plainReqs := startFakeICAP(t, nil, reply)
	if err := trusted.Probe(context.Background(), config.ICAPServer{Address: plainAddr, UseTLS: true}); err == nil {
		t.Fatal("TLS probe fell back to plaintext")
	}
	select {
	case req := <-plainReqs:
		t.Fatalf("plaintext server received a request: %+v", req)
	default:
	}
	// TLS below 1.2 is refused.
	old := ca.serverConfig(t, "localhost")
	old.MinVersion, old.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
	oldAddr, _ := startFakeICAP(t, old, reply)
	_, oldPort, _ := net.SplitHostPort(oldAddr)
	if err := trusted.Probe(context.Background(), config.ICAPServer{Address: net.JoinHostPort("localhost", oldPort), UseTLS: true}); err == nil {
		t.Fatal("Probe accepted TLS < 1.2")
	}
}
