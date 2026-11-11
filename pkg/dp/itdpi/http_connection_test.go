// SPDX-License-Identifier: Apache-2.0

package itdpi

import (
	"bytes"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestHTTPHeaderOnlyRecoveryAcrossSplits(t *testing.T) {
	raw := []byte("body bytesHTTP/invalid\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\nmore body\r\nHTTP/1.1 204 No Content\r\n\r\n")
	for split := 0; split <= len(raw); split++ {
		d := NewHTTPDecoder()
		mgr := dpi.NewManager(d)
		client := httpFlowState(12345, 80)
		server := httpFlowState(80, 12345)
		server.Key.SrcIP, server.Key.DstIP = client.Key.DstIP, client.Key.SrcIP
		req := bytes.Repeat([]byte("HEAD / HTTP/1.1\r\n\r\n"), maxHTTPRequestMethods+1)
		mgr.Inspect(client, &dpi.ParsedPacket{Proto: "tcp", Payload: req, TCPSeqValid: true, TCPSeq: 100})
		// Establish header-only inspection before fragmented unknown bodies.
		prime := []byte("HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n")
		mgr.Inspect(server, &dpi.ParsedPacket{Proto: "tcp", Payload: prime, TCPSeqValid: true, TCPSeq: 200})
		var events []dpi.Event
		seq := uint32(200 + len(prime))
		for _, p := range [][]byte{raw[:split], raw[split:]} {
			r := mgr.Inspect(server, &dpi.ParsedPacket{Proto: "tcp", Payload: p, TCPSeqValid: true, TCPSeq: seq})
			seq += uint32(len(p))
			if r.Err != nil {
				t.Fatal(r.Err)
			}
			events = append(events, r.Events...)
		}
		if len(events) != 2 || events[0].Kind != "response" || events[1].Attributes["status"] != "204" {
			t.Fatalf("split %d: %v", split, events)
		}
	}
}

func TestHTTPDroppedRequestCounterSaturates(t *testing.T) {
	c := httpConnection{dropped: ^uint64(0)}
	c.request(httpStreamKey{}, "HEAD", nil)
	c.response()
	if c.dropped != ^uint64(0) || c.pending().method != "" || c.opaque {
		t.Fatalf("counter wrapped or ended inspection: %+v", c)
	}
}

func TestHTTPUpgradeCorrelationClearsOnFinalResponse(t *testing.T) {
	c := httpConnection{}
	c.request(httpStreamKey{}, "GET", map[string]string{"connection": "Upgrade", "upgrade": "websocket, custom/V1"})
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
	c.request(httpStreamKey{}, "GET", nil)
	if c.pending().acceptsUpgrade(map[string]string{"connection": "Upgrade", "upgrade": "websocket"}) {
		t.Fatal("upgrade leaked to the following request")
	}
}
