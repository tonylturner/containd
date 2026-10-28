// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package services

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func icapReply(lines ...string) func(icapRequest) string {
	return func(icapRequest) string { return strings.Join(lines, "\r\n") + "\r\n\r\n" }
}

// icapServer is a plaintext server with the default service.
func icapServer(addr string) config.ICAPServer {
	return config.ICAPServer{Address: addr, Service: "avscan"}
}

func TestICAPScanVerdicts(t *testing.T) {
	payload := []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	infected := "Encapsulated: res-hdr=0, res-body=41"
	cases := []struct {
		name      string
		reply     func(icapRequest) string
		verdict   string
		signature string
		errPart   string
	}{
		{name: "204 clean", reply: icapReply("ICAP/1.0 204 No Content", "ISTag: \"t1\""), verdict: "clean"},
		{name: "infection found", reply: icapReply("ICAP/1.0 200 OK", "X-Infection-Found: Type=0; Resolution=2; Threat=Eicar-Test-Signature;", "X-Violations-Found: 1", infected), verdict: "malware", signature: "Eicar-Test-Signature"},
		{name: "violations only", reply: icapReply("ICAP/1.0 200 OK", "X-Violations-Found: 1", infected), verdict: "malware"},
		{name: "legacy virus id", reply: icapReply("ICAP/1.0 200 OK", "X-Virus-ID: Win.Test.EICAR_HDB-1", infected), verdict: "malware", signature: "Win.Test.EICAR_HDB-1"},
		{name: "legacy status", reply: icapReply("ICAP/1.0 200 OK", "X-ICAP-Status: VirusFound", infected), verdict: "malware"},
		{name: "204 with infection header", reply: icapReply("ICAP/1.0 204 No Content", "X-Infection-Found: Type=0; Resolution=2; Threat=Test;"), verdict: "malware", signature: "Test"},
		{name: "200 echo", reply: icapReply("ICAP/1.0 200 OK", infected), errPart: "without an infection header"},
		{name: "server error", reply: icapReply("ICAP/1.0 500 Server Error"), errPart: "unexpected status 500"},
		{name: "not found", reply: icapReply("ICAP/1.0 404 ICAP Service Not Found"), errPart: "unexpected status 404"},
		{name: "truncated headers", reply: func(icapRequest) string { return "ICAP/1.0 204 No Content\r\nISTag: x\r\n" }, errPart: "truncated"},
		{name: "truncated status", reply: func(icapRequest) string { return "ICAP/1.0 2" }, errPart: "status"},
		{name: "close before reply", reply: func(icapRequest) string { return "" }, errPart: "truncated"},
		{name: "not icap", reply: icapReply("HTTP/1.1 200 OK"), errPart: "malformed status"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, reqs := startFakeICAP(t, nil, tc.reply)
			res, err := (&ICAPClient{Timeout: time.Second}).Scan(context.Background(), icapServer(addr), scanObject(payload))
			if tc.errPart != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errPart) {
					t.Fatalf("Scan() = %+v, %v; want error containing %q", res, err, tc.errPart)
				}
			} else if err != nil || res.Verdict != tc.verdict || res.Signature != tc.signature {
				t.Fatalf("Scan() = %+v, %v; want %s/%s", res, err, tc.verdict, tc.signature)
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

func TestICAPScanEncapsulatesUploadAsREQMOD(t *testing.T) {
	addr, reqs := startFakeICAP(t, nil, icapReply("ICAP/1.0 204 No Content"))
	obj := uploadObject([]byte("form payload"))
	if res, err := (&ICAPClient{Timeout: time.Second}).Scan(context.Background(), icapServer(addr), obj); err != nil || res.Verdict != "clean" {
		t.Fatalf("Scan(upload) = %+v, %v", res, err)
	}
	req := <-reqs
	wantHead := "POST /upload HTTP/1.1\r\nHost: files.example\r\nContent-Encoding: gzip\r\nContent-Length: 12\r\n\r\n"
	if req.Method != "REQMOD" || req.ReqHeader != wantHead || req.ResHeader != "" {
		t.Fatalf("REQMOD request = %+v", req)
	}
	if want := fmt.Sprintf("req-hdr=0, req-body=%d", len(wantHead)); req.Encapsulated != want {
		t.Fatalf("Encapsulated = %q, want %q", req.Encapsulated, want)
	}
	if req.Header.Get("X-Client-IP") != "10.1.2.3" || req.Header.Get("X-Server-IP") != "192.0.2.10" {
		t.Fatalf("client/server headers = %q / %q", req.Header.Get("X-Client-IP"), req.Header.Get("X-Server-IP"))
	}
	if string(req.Body) != "form payload" {
		t.Fatalf("body = %q", req.Body)
	}
}

func TestICAPScanEncapsulatesDownloadAsRESPMOD(t *testing.T) {
	addr, reqs := startFakeICAP(t, nil, icapReply("ICAP/1.0 204 No Content"))
	client := &ICAPClient{Timeout: time.Second}
	obj := scanObject([]byte("downloaded bytes"))
	if res, err := client.Scan(context.Background(), icapServer(addr), obj); err != nil || res.Verdict != "clean" {
		t.Fatalf("Scan(download) = %+v, %v", res, err)
	}
	req := <-reqs
	wantRes := "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 16\r\n\r\n"
	if req.Method != "RESPMOD" || req.ReqHeader != string(obj.RequestHead) || req.ResHeader != wantRes {
		t.Fatalf("RESPMOD request = %+v", req)
	}
	if want := fmt.Sprintf("req-hdr=0, res-hdr=%d, res-body=%d", len(obj.RequestHead), len(obj.RequestHead)+len(wantRes)); req.Encapsulated != want {
		t.Fatalf("Encapsulated = %q, want %q", req.Encapsulated, want)
	}
	if req.Header.Get("X-Client-IP") != "10.1.2.3" || req.Header.Get("X-Server-IP") != "192.0.2.10" {
		t.Fatalf("client/server headers = %q / %q", req.Header.Get("X-Client-IP"), req.Header.Get("X-Server-IP"))
	}

	// Without a request head only the response is encapsulated; without
	// addresses the IP headers are omitted.
	obj.RequestHead = nil
	obj.Client, obj.Server = netip.AddrPort{}, netip.AddrPort{}
	if res, err := client.Scan(context.Background(), icapServer(addr), obj); err != nil || res.Verdict != "clean" {
		t.Fatalf("Scan(download without request head) = %+v, %v", res, err)
	}
	req = <-reqs
	if req.ReqHeader != "" || req.ResHeader != wantRes || req.Encapsulated != fmt.Sprintf("res-hdr=0, res-body=%d", len(wantRes)) {
		t.Fatalf("RESPMOD without request head = %+v", req)
	}
	if _, ok := req.Header["X-Client-Ip"]; ok {
		t.Fatalf("X-Client-IP sent without a client address: %+v", req.Header)
	}
	if _, ok := req.Header["X-Server-Ip"]; ok {
		t.Fatalf("X-Server-IP sent without a server address: %+v", req.Header)
	}
}

func TestICAPScanZeroSizeBodyUsesNullBody(t *testing.T) {
	addr, reqs := startFakeICAP(t, nil, icapReply("ICAP/1.0 204 No Content"))
	client := &ICAPClient{Timeout: time.Second}
	for _, obj := range []avscan.Object{uploadObject(nil), scanObject(nil)} {
		if res, err := client.Scan(context.Background(), icapServer(addr), obj); err != nil || res.Verdict != "clean" {
			t.Fatalf("Scan(empty %s) = %+v, %v", obj.Direction, res, err)
		}
		req := <-reqs
		if !req.NullBody || len(req.Body) != 0 || !strings.Contains(req.Encapsulated, "null-body=") {
			t.Fatalf("empty %s: Encapsulated = %q body %q", obj.Direction, req.Encapsulated, req.Body)
		}
		if strings.Contains(req.ReqHeader+req.ResHeader, "Transfer-Encoding") {
			t.Fatalf("empty %s kept transfer framing: %+v", obj.Direction, req)
		}
	}
}

func TestICAPScanRejectsIncompleteObjects(t *testing.T) {
	addr, reqs := startFakeICAP(t, nil, icapReply("ICAP/1.0 204 No Content"))
	client := &ICAPClient{Timeout: time.Second}
	noDirection := scanObject([]byte("x"))
	noDirection.Direction = ""
	noRequest := uploadObject([]byte("x"))
	noRequest.RequestHead = nil
	noResponse := scanObject([]byte("x"))
	noResponse.ResponseHead = nil
	badHead := scanObject([]byte("x"))
	badHead.ResponseHead = []byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n")
	folded := uploadObject([]byte("x"))
	folded.RequestHead = []byte("POST / HTTP/1.1\r\nHost: a\r\n b\r\n\r\n")
	short := scanObject([]byte("short"))
	short.Size++
	for name, obj := range map[string]avscan.Object{
		"no direction": noDirection, "upload without request head": noRequest, "download without response head": noResponse,
		"head without blank line": badHead, "folded head": folded, "body shorter than size": short,
	} {
		start := time.Now()
		if res, err := client.Scan(context.Background(), icapServer(addr), obj); err == nil {
			t.Fatalf("%s: Scan() = %+v, want error", name, res)
		}
		if time.Since(start) > 500*time.Millisecond {
			t.Fatalf("%s: waited %s for a reply that cannot come", name, time.Since(start))
		}
	}
	select {
	case req := <-reqs:
		t.Fatalf("server accepted an incomplete object: %+v", req)
	default:
	}
}

// boundedReaderAt records the largest single read so streaming is observable.
type boundedReaderAt struct {
	io.ReaderAt
	maxRead atomic.Int64
}

func (b *boundedReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if n := int64(len(p)); n > b.maxRead.Load() {
		b.maxRead.Store(n)
	}
	return b.ReaderAt.ReadAt(p, off)
}

func TestICAPScanStreamsLargeBody(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789abcdef"), (5*icapChunkSize)/16+7)
	got := make(chan []byte, 1)
	addr, _ := startFakeICAP(t, nil, func(req icapRequest) string {
		got <- req.Body
		return "ICAP/1.0 204 No Content\r\n\r\n"
	})
	src := &boundedReaderAt{ReaderAt: bytes.NewReader(payload)}
	obj := scanObject(payload)
	obj.Body = src
	if res, err := (&ICAPClient{Timeout: time.Second}).Scan(context.Background(), icapServer(addr), obj); err != nil || res.Verdict != "clean" {
		t.Fatalf("Scan(large) = %+v, %v", res, err)
	}
	if !bytes.Equal(<-got, payload) {
		t.Fatal("server did not receive the identical body")
	}
	if src.maxRead.Load() > icapChunkSize {
		t.Fatalf("body read in %d-byte pieces, want at most %d", src.maxRead.Load(), icapChunkSize)
	}
}

func TestICAPScanDeadlines(t *testing.T) {
	slow := func(d time.Duration) func(icapRequest) string {
		return func(icapRequest) string {
			time.Sleep(d)
			return "ICAP/1.0 204 No Content\r\n\r\n"
		}
	}
	bounded := func(t *testing.T, name string, client *ICAPClient, ctx context.Context, addr string) {
		t.Helper()
		start := time.Now()
		res, err := client.Scan(ctx, icapServer(addr), scanObject([]byte("x")))
		if err == nil {
			t.Fatalf("%s: Scan() = %+v, want a timeout", name, res)
		}
		var ne net.Error
		if !(errors.As(err, &ne) && ne.Timeout()) && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("%s: error %v is not a timeout", name, err)
		}
		if elapsed := time.Since(start); elapsed > 1200*time.Millisecond {
			t.Fatalf("%s: deadline not honoured: %s", name, elapsed)
		}
	}
	addr, _ := startFakeICAP(t, nil, slow(1500*time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	bounded(t, "caller deadline", &ICAPClient{Timeout: 5 * time.Second}, ctx, addr)
	bounded(t, "timeout without caller deadline", &ICAPClient{Timeout: 300 * time.Millisecond}, context.Background(), addr)

	// The caller's deadline governs a scan that outlasts Timeout.
	patient, cancelPatient := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelPatient()
	addr, _ = startFakeICAP(t, nil, slow(400*time.Millisecond))
	if res, err := (&ICAPClient{Timeout: 100 * time.Millisecond}).Scan(patient, icapServer(addr), scanObject([]byte("x"))); err != nil || res.Verdict != "clean" {
		t.Fatalf("scan under the caller's deadline = %+v, %v", res, err)
	}

	// Cancellation interrupts the wait for a reply.
	addr, _ = startFakeICAP(t, nil, slow(1500*time.Millisecond))
	cancelled, cancelNow := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancelNow)
	start := time.Now()
	if res, err := (&ICAPClient{Timeout: 5 * time.Second}).Scan(cancelled, icapServer(addr), scanObject([]byte("x"))); err == nil {
		t.Fatalf("cancelled scan = %+v", res)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("cancellation did not interrupt the read: %s", time.Since(start))
	}
}

func TestICAPOptionsProbe(t *testing.T) {
	addr, reqs := startFakeICAP(t, nil, icapReply("ICAP/1.0 200 OK", "Methods: RESPMOD", "Encapsulated: null-body=0"))
	if err := (&ICAPClient{Timeout: time.Second}).Probe(context.Background(), config.ICAPServer{Address: addr, Service: "/scan"}, icapRESPMOD); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	req := <-reqs
	if req.Method != "OPTIONS" || req.URI != "icap://"+addr+"/scan" || req.Encapsulated != "null-body=0" {
		t.Fatalf("OPTIONS request = %+v", req)
	}
	for name, tc := range map[string]struct {
		reply    func(icapRequest) string
		required []string
		errPart  string
	}{
		"respmod only, uploads scanned":    {icapReply("ICAP/1.0 200 OK", "Methods: RESPMOD", "Encapsulated: null-body=0"), []string{icapREQMOD}, "REQMOD"},
		"respmod only, both scanned":       {icapReply("ICAP/1.0 200 OK", "Methods: RESPMOD", "Encapsulated: null-body=0"), []string{icapREQMOD, icapRESPMOD}, "REQMOD"},
		"reqmod only, downloads scanned":   {icapReply("ICAP/1.0 200 OK", "Methods: REQMOD", "Encapsulated: null-body=0"), []string{icapRESPMOD}, "RESPMOD"},
		"both listed, both scanned":        {icapReply("ICAP/1.0 200 OK", "Methods: REQMOD, RESPMOD", "Encapsulated: null-body=0"), []string{icapREQMOD, icapRESPMOD}, ""},
		"lower case list":                  {icapReply("ICAP/1.0 200 OK", "Methods: respmod,reqmod", "Encapsulated: null-body=0"), []string{icapREQMOD, icapRESPMOD}, ""},
		"methods not listed":               {icapReply("ICAP/1.0 200 OK", "Encapsulated: null-body=0"), []string{icapREQMOD, icapRESPMOD}, ""},
		"nothing scanned":                  {icapReply("ICAP/1.0 200 OK", "Methods: REQMOD", "Encapsulated: null-body=0"), nil, ""},
		"not found":                        {icapReply("ICAP/1.0 404 ICAP Service Not Found"), nil, "unexpected status 404"},
		"server error":                     {icapReply("ICAP/1.0 500 Server Error"), []string{icapRESPMOD}, "unexpected status 500"},
		"truncated":                        {func(icapRequest) string { return "ICAP/1.0 200 OK\r\nMethods: RESPMOD\r\n" }, nil, "truncated"},
		"closed before reply":              {func(icapRequest) string { return "" }, nil, "truncated"},
		"respmod only, downloads scanned ": {icapReply("ICAP/1.0 200 OK", "Methods: RESPMOD", "Encapsulated: null-body=0"), []string{icapRESPMOD}, ""},
	} {
		t.Run(strings.TrimSpace(name), func(t *testing.T) {
			addr, _ := startFakeICAP(t, nil, tc.reply)
			err := (&ICAPClient{Timeout: time.Second}).Probe(context.Background(), config.ICAPServer{Address: addr}, tc.required...)
			if tc.errPart == "" && err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if tc.errPart != "" && (err == nil || !strings.Contains(err.Error(), tc.errPart)) {
				t.Fatalf("Probe = %v, want error containing %q", err, tc.errPart)
			}
		})
	}
}

func TestICAPProbeKeepsItsOwnBound(t *testing.T) {
	addr, _ := startFakeICAP(t, nil, func(icapRequest) string {
		time.Sleep(1500 * time.Millisecond)
		return "ICAP/1.0 200 OK\r\nEncapsulated: null-body=0\r\n\r\n"
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := (&ICAPClient{Timeout: 200 * time.Millisecond}).Probe(ctx, config.ICAPServer{Address: addr}); err == nil {
		t.Fatal("slow OPTIONS reply accepted")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("probe outlived its Timeout: %s", elapsed)
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
		if _, err := client.Scan(context.Background(), srv, scanObject([]byte("x"))); err == nil {
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
	if err := trusted.Probe(context.Background(), named, icapRESPMOD); err != nil {
		t.Fatalf("Probe over TLS: %v", err)
	}
	<-reqs
	if res, err := trusted.Scan(context.Background(), named, scanObject([]byte("data"))); err != nil || res.Verdict != "clean" {
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

func TestDescribeBodyRewritesFraming(t *testing.T) {
	for name, tc := range map[string]struct {
		head string
		size int64
		want string
	}{
		"chunked becomes content-length": {"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n", 7, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 7\r\n\r\n"},
		"content-length replaced":        {"POST /u HTTP/1.1\r\ncontent-length : 999\r\nHost: h\r\n\r\n", 3, "POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\n"},
		"empty body drops framing":       {"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n", 0, "HTTP/1.1 204 No Content\r\n\r\n"},
		"other fields untouched":         {"GET / HTTP/1.1\r\nHost: h\r\nX-Content-Length-Hint: 5\r\n\r\n", 0, "GET / HTTP/1.1\r\nHost: h\r\nX-Content-Length-Hint: 5\r\n\r\n"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := describeBody([]byte(tc.head), tc.size)
			if err != nil || string(got) != tc.want {
				t.Fatalf("describeBody = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	for name, head := range map[string]string{
		"no blank line":      "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n",
		"bytes after head":   "HTTP/1.1 200 OK\r\n\r\nbody",
		"empty start line":   "\r\nHost: h\r\n\r\n",
		"folded field":       "GET / HTTP/1.1\r\nHost: h\r\n continued\r\n\r\n",
		"field without name": "GET / HTTP/1.1\r\n: v\r\n\r\n",
		"bare lf":            "GET / HTTP/1.1\nHost: h\n\n",
	} {
		if got, err := describeBody([]byte(head), 1); err == nil {
			t.Fatalf("%s: describeBody accepted %q as %q", name, head, got)
		}
	}
}

func TestICAPInfectionHeaders(t *testing.T) {
	for name, tc := range map[string]struct {
		header    textproto.MIMEHeader
		found     bool
		signature string
	}{
		"none":                    {textproto.MIMEHeader{"Istag": {"x"}}, false, ""},
		"threat parameter":        {textproto.MIMEHeader{"X-Infection-Found": {"Type=0; Resolution=2; Threat=Eicar-Test-Signature;"}}, true, "Eicar-Test-Signature"},
		"threat without params":   {textproto.MIMEHeader{"X-Infection-Found": {"Type=0"}}, true, ""},
		"virus id":                {textproto.MIMEHeader{"X-Virus-Id": {" Test.Sig "}}, true, "Test.Sig"},
		"threat beats virus id":   {textproto.MIMEHeader{"X-Infection-Found": {"Threat=A"}, "X-Virus-Id": {"B"}}, true, "A"},
		"violations":              {textproto.MIMEHeader{"X-Violations-Found": {"1 /f Eicar 0 2"}}, true, ""},
		"status":                  {textproto.MIMEHeader{"X-Icap-Status": {"virusfound"}}, true, ""},
		"status without a threat": {textproto.MIMEHeader{"X-Icap-Status": {"Clean"}}, false, ""},
	} {
		sig, found := icapInfection(tc.header)
		if found != tc.found || sig != tc.signature {
			t.Fatalf("%s: icapInfection = %q, %v; want %q, %v", name, sig, found, tc.signature, tc.found)
		}
	}
}
