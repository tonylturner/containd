// SPDX-License-Identifier: Apache-2.0

package itdpi

import (
	"bytes"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestHTTPUncertainBodyReanchorsOnlyAtPacketStart(t *testing.T) {
	raw := []byte("body bytesHTTP/invalid\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\nmore body\r\nHTTP/1.1 204 No Content\r\n\r\n")
	for split := 0; split <= len(raw); split++ {
		d := NewHTTPDecoder()
		mgr := dpi.NewManager(d)
		client := httpFlowState(12345, 80)
		server := httpFlowState(80, 12345)
		server.Key.SrcIP, server.Key.DstIP = client.Key.DstIP, client.Key.SrcIP
		seq := uint32(200)
		send := func(p []byte) dpi.InspectResult {
			r := mgr.Inspect(server, &dpi.ParsedPacket{Proto: "tcp", Payload: p, TCPSeqValid: true, TCPSeq: seq})
			seq += uint32(len(p))
			if r.Err != nil {
				t.Fatal(r.Err)
			}
			return r
		}
		req := bytes.Repeat([]byte("HEAD / HTTP/1.1\r\n\r\n"), maxHTTPRequestMethods+1)
		mgr.Inspect(client, &dpi.ParsedPacket{Proto: "tcp", Payload: req, TCPSeqValid: true, TCPSeq: 100})
		// Drain the known HEAD prefix; only the overflowed method is unknown.
		for i := 0; i < maxHTTPRequestMethods; i++ {
			send([]byte("HTTP/1.1 204 No Content\r\n\r\n"))
		}
		// A length on the unknown reply might describe a HEAD representation.
		prime := []byte("HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n")
		send(prime)
		var events []dpi.Event

		for _, p := range [][]byte{raw[:split], raw[split:]} {
			r := send(append([]byte{0xee}, p...))
			if r.Err != nil {
				t.Fatal(r.Err)
			}
			events = append(events, r.Events...)
		}
		if len(events) != 0 {
			t.Fatalf("split %d: %v", split, events)
		}
		r := send([]byte("HTTP/1.1 204 No Content\r\n\r\n"))
		if len(r.Events) != 1 || r.Events[0].Attributes["status"] != "204" {
			t.Fatalf("no packet-boundary recovery: %+v", r)
		}
	}
}

func TestHTTPDroppedRequestCounterSaturates(t *testing.T) {
	c := httpConnection{dropped: ^uint64(0)}
	if err := c.request(&httpStream{id: 1}, "HEAD", nil); err != nil {
		t.Fatal(err)
	}
	c.response()
	if c.dropped != ^uint64(0) || c.pending().method != "" {
		t.Fatalf("counter wrapped or ended inspection: %+v", c)
	}
}

func TestHTTPUpgradeCorrelationClearsOnFinalResponse(t *testing.T) {
	c := httpConnection{}
	defer c.clearRequests()
	if err := c.request(&httpStream{id: 1}, "GET", map[string]string{"connection": "Upgrade", "upgrade": "websocket, custom/V1"}); err != nil {
		t.Fatal(err)
	}
	for _, selected := range []string{"WebSocket", "custom/V1, WebSocket"} {
		if !c.pending().acceptsUpgrade(map[string]string{"connection": "keep-alive, upgrade", "upgrade": selected}) {
			t.Fatalf("matching upgrade not accepted: %s", selected)
		}
	}
	for _, selected := range []string{"custom/v1", "WebSocket, unoffered", "WebSocket,", "web socket", "/V1", "custom/"} {
		if c.pending().acceptsUpgrade(map[string]string{"connection": "Upgrade", "upgrade": selected}) {
			t.Fatalf("invalid or unoffered upgrade accepted: %s", selected)
		}
	}
	c.response()
	if err := c.request(&httpStream{id: 1}, "GET", nil); err != nil {
		t.Fatal(err)
	}
	if c.pending().acceptsUpgrade(map[string]string{"connection": "Upgrade", "upgrade": "websocket"}) {
		t.Fatal("upgrade leaked to the following request")
	}
}

func TestHTTPUncertainCorrelationCannotAuthorizeTunnel(t *testing.T) {
	for _, connect := range []bool{false, true} {
		d := NewHTTPDecoder()
		mgr := dpi.NewManager(d)
		client, server := httpFlowState(12345, 80), httpFlowState(80, 12345)
		server.Key.SrcIP, server.Key.DstIP = client.Key.DstIP, client.Key.SrcIP
		seq := [2]uint32{100, 200}
		send := func(reply bool, p string) dpi.InspectResult {
			i, st, role := 0, client, dpi.ClientToServer
			if reply {
				i, st, role = 1, server, dpi.ServerToClient
			}
			r := mgr.Inspect(st, &dpi.ParsedPacket{Proto: "tcp", Payload: []byte(p), TCPSeqValid: true, TCPSeq: seq[i], Role: role})
			seq[i] += uint32(len(p))
			if r.Err != nil {
				t.Fatal(r.Err)
			}
			return r
		}
		for i := 0; i < maxHTTPRequestMethods+1; i++ {
			send(false, "HEAD / HTTP/1.1\r\n\r\n")
		}
		for i := 0; i < maxHTTPRequestMethods; i++ {
			send(true, "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n")
		}
		// This last method was lost. Following packet boundaries may produce
		// metadata, but cannot prove that the outstanding real bodies drained.
		send(true, "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n")
		for i := 0; i < 64; i++ {
			send(true, "HTTP/1.1 204 No Content\r\n\r\n")
		}
		req := "GET /ws HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
		rep := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
		if connect {
			req, rep = "CONNECT example.test:443 HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n"
		}
		send(false, req)
		send(true, rep)
		for _, s := range d.streams {
			if s.resync || !s.peer.uncertain {
				t.Fatal("speculative metadata authorized a tunnel")
			}
		}
	}
}

func TestHTTPMatchingTunnelTransition(t *testing.T) {
	for _, connect := range []bool{false, true} {
		d := NewHTTPDecoder()
		mgr := dpi.NewManager(d)
		client, server := httpFlowState(12345, 80), httpFlowState(80, 12345)
		server.Key.SrcIP, server.Key.DstIP = client.Key.DstIP, client.Key.SrcIP
		seq := [2]uint32{100, 200}
		send := func(reply bool, p string) dpi.InspectResult {
			i, st := 0, client
			if reply {
				i, st = 1, server
			}
			r := mgr.Inspect(st, &dpi.ParsedPacket{Proto: "tcp", Payload: []byte(p), TCPSeqValid: true, TCPSeq: seq[i]})
			seq[i] += uint32(len(p))
			if r.Err != nil {
				t.Fatal(r.Err)
			}
			return r
		}
		req := "GET /ws HTTP/1.1\r\nConnection: Upgrade\r\nConnection: keep-alive\r\nUpgrade: custom/V1\r\nUpgrade: websocket\r\n\r\n"
		rep := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nConnection: keep-alive\r\nUpgrade: custom/V1\r\nUpgrade: websocket\r\n\r\n"
		if connect {
			req, rep = "CONNECT example.test:443 HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n"
		}
		send(false, "GET /first HTTP/1.1\r\n\r\n"+req)
		send(true, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		for _, s := range d.streams {
			if s.resync {
				t.Fatal("reply to an earlier request opened the tunnel")
			}
		}
		send(true, rep)
		for _, s := range d.streams {
			if !s.resync {
				t.Fatal("matching reply did not open the tunnel")
			}
		}
		if r := send(false, "\xee\xee\xee\r\n\r\n"); len(r.Events) != 0 {
			t.Fatal("binary tunnel data emitted events", r)
		}
		if r := send(false, "GET /after HTTP/1.1\r\n\r\n"); len(r.Events) != 1 || r.Events[0].Attributes["path"] != "/after" {
			t.Fatal("tunnel failed to re-anchor", r)
		}
	}
}

func TestHTTPUncertainResponseCannotRejectDeclaredBody(t *testing.T) {
	body := &httpBody{incomplete: true}
	c := httpConnection{uncertain: true, methods: []httpRequest{{method: "POST", body: body}}}
	c.response()
	if body.rejected {
		t.Fatal("an uncertain final response abandoned a declared body")
	}
}
