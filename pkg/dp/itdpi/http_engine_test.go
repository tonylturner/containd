// SPDX-License-Identifier: Apache-2.0

package itdpi_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type metadataEngine struct {
	e    *engine.Engine
	port uint16
	seq  [2]uint32
}

func newMetadataEngine(t *testing.T, port uint16) *metadataEngine {
	t.Helper()
	e, err := engine.New(engine.Config{InspectAll: true, DPIEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	e.LoadRules(rules.Snapshot{Default: rules.ActionAllow})
	return &metadataEngine{e: e, port: port, seq: [2]uint32{1000, 2000}}
}
func (h *metadataEngine) send(t *testing.T, reply bool, payload []byte) {
	t.Helper()
	i := 0
	if reply {
		i = 1
	}
	src, dst := net.IPv4(10, 0, 0, 1).To4(), net.IPv4(10, 0, 0, 2).To4()
	sport, dport := uint16(40000), h.port
	if reply {
		src, dst = dst, src
		sport, dport = dport, sport
	}
	decision := h.e.HandlePacket(capture.Packet{Timestamp: time.Now(), IPVersion: 4, SrcIP: src, DstIP: dst, SrcPort: sport, DstPort: dport, PortsValid: true, Proto: 6, Transport: "tcp", Payload: payload, TCP: capture.TCPMeta{Valid: true, Seq: h.seq[i], Flags: capture.TCPFlagACK}})
	h.seq[i] += uint32(len(payload))
	if decision.Action != capture.Accept {
		t.Fatalf("metadata changed forwarding: %+v", decision)
	}
}
func (h *metadataEngine) want(t *testing.T, proto string, counts map[string]int) {
	t.Helper()
	actual := map[string]int{}
	all := h.e.Events().List(100000)
	expected := 0
	for _, n := range counts {
		expected += n
	}
	if len(all) != expected {
		t.Fatalf("store holds %d events, want %d: %v", len(all), expected, all)
	}
	for _, ev := range all {
		if ev.Proto == proto {
			actual[ev.Kind]++
		}
	}
	if len(actual) != len(counts) {
		t.Fatalf("events: got %v want %v", actual, counts)
	}
	for kind, n := range counts {
		if actual[kind] != n {
			t.Fatalf("events: got %v want %v", actual, counts)
		}
	}
}

func TestTLSLegacyEnginePickupsStaySilent(t *testing.T) {
	for _, prefix := range []byte{0, 0xee} {
		t.Run(map[byte]string{0: "non_TLS", 0xee: "mid_record"}[prefix], func(t *testing.T) {
			h := newMetadataEngine(t, 443)
			payload := bytes.Repeat([]byte{prefix}, 1400)
			for i := 0; i < 6000; i++ {
				h.send(t, false, payload)
			}
			h.want(t, "tls", map[string]int{})
		})
	}
}

func TestTLSLegacyEngineStopsAfterOneMalformed(t *testing.T) {
	h := newMetadataEngine(t, 443)
	// Minimal TLS 1.2 hello, two ciphers and no extensions.
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 4, 0x13, 1, 0xc0, 0x2f, 1, 0, 0, 0)
	hs := append([]byte{1, 0, 0, byte(len(body))}, body...)
	record := append([]byte{22, 3, 3, 0, byte(len(hs))}, hs...)
	h.send(t, false, record)
	for i := 0; i < 6000; i++ {
		h.send(t, false, bytes.Repeat([]byte{0xee}, 1400))
	}
	h.want(t, "tls", map[string]int{"client_hello": 1, "malformed": 1})
}

func TestHTTPLegacyEnginePickupsAndTunnels(t *testing.T) {
	for _, tc := range []struct {
		name, request, response string
		want                    map[string]int
	}{
		{"mid_body", "", "", map[string]int{}},
		{"CONNECT", "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n", "HTTP/1.1 200 Connection Established\r\nContent-Length: 4096\r\n\r\n", map[string]int{"request": 1, "response": 1}},
		{"websocket", "GET /ws HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", map[string]int{"request": 1, "response": 1}},
		{"other_101", "GET / HTTP/1.1\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket, custom\r\n\r\n", "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: custom, websocket\r\n\r\n", map[string]int{"request": 1, "response": 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newMetadataEngine(t, 80)
			if tc.request != "" {
				h.send(t, false, []byte(tc.request))
			}
			if tc.response != "" {
				h.send(t, true, []byte(tc.response))
			}
			payload := append(bytes.Repeat([]byte{0xee}, 1396), '\r', '\n', '\r', '\n')
			for i := 0; i < 6000; i++ {
				h.send(t, i%2 == 0, payload)
			}
			h.want(t, "http", tc.want)
			h.send(t, false, []byte("GET /inside-tunnel HTTP/1.1\r\n\r\n"))
			tc.want["request"]++
			h.want(t, "http", tc.want)
		})
	}
}

func TestHTTPLegacyEngineStopsAfterOneMalformed(t *testing.T) {
	h := newMetadataEngine(t, 80)
	h.send(t, false, []byte("GET / HTTP/1.1\r\n\r\n"))
	payload := []byte("not HTTP\r\n\r\n")
	for i := 0; i < 6000; i++ {
		h.send(t, false, payload)
	}
	h.want(t, "http", map[string]int{"request": 1, "malformed": 1})
}

func TestHTTPLegacyEngineHEADAndBareLF(t *testing.T) {
	h := newMetadataEngine(t, 80)
	h.send(t, false, []byte("\r\n\nHEAD /head HTTP/1.1\nHost: v\n\nGET /next HTTP/1.1\nHost: v\n\n"))
	h.send(t, true, []byte("HTTP/1.1 100 Continue\nContent-Length: 4096\n\nHTTP/1.1 200 OK\nContent-Length: 4096\n\nHTTP/1.1 200 OK\nContent-Length: 2\nContent-Type: text/plain\n\nok"))
	h.want(t, "http", map[string]int{"request": 2, "response": 3})
	found := false
	for _, ev := range h.e.Events().List(100000) {
		if ev.Proto == "http" && ev.Attributes["content_type"] == "text/plain" {
			found = true
		}
	}
	if !found {
		t.Fatal("response following HEAD was not inspected")
	}
}
