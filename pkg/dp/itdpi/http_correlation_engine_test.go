// SPDX-License-Identifier: Apache-2.0

package itdpi_test

import (
	"fmt"
	"testing"
)

func TestHTTPLegacyEngineCorrelationOverflow(t *testing.T) {
	h := newMetadataEngine(t, 80)
	for i := 0; i < 65; i++ {
		h.send(t, false, []byte(fmt.Sprintf("GET /%d HTTP/1.1\r\n\r\n", i)))
	}
	for i := 0; i < 65; i++ {
		h.send(t, true, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	}
	h.send(t, false, []byte("HEAD /after HTTP/1.1\r\n\r\nGET /last HTTP/1.1\r\n\r\n"))
	h.send(t, true, []byte("HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	h.want(t, "http", map[string]int{"request": 67, "response": 67})
}

func TestHTTPLegacyEngineOverflowHeaderOnlyResponses(t *testing.T) {
	h := newMetadataEngine(t, 80)
	for i := 0; i < 65; i++ {
		h.send(t, false, []byte("HEAD / HTTP/1.1\r\n\r\n"))
	}
	// Once correlation is lost, lengths must not hide following headers.
	// Actual body bytes must not terminate this header-only inspection either.
	for i := 0; i < 65; i++ {
		h.send(t, true, []byte("HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n"))
		if i == 1 {
			h.send(t, true, []byte("unattributed body bytes"))
		}
	}
	h.send(t, false, []byte("GET /after HTTP/1.1\r\n\r\n"))
	h.send(t, true, []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	h.want(t, "http", map[string]int{"request": 66, "response": 66})
}

func TestHTTPLegacyEngineWrongDirectionResponse(t *testing.T) {
	for _, tc := range []struct {
		name, priorRequest string
	}{
		{"reply_first", ""},
		{"plain_request", "GET /first HTTP/1.1\r\n\r\n"},
		{"upgrade_request", "GET /ws HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"},
	} {
		t.Run("101_"+tc.name, func(t *testing.T) {
			h := newMetadataEngine(t, 80)
			requests, responses := 1, 2
			if tc.priorRequest != "" {
				h.send(t, false, []byte(tc.priorRequest))
				requests, responses = 2, 1
			}
			h.send(t, false, []byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"))
			h.send(t, false, []byte("GET /after HTTP/1.1\r\n\r\n"))
			h.send(t, true, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			// Before any request there is no established role: reply-only
			// metadata remains useful, but it cannot establish a tunnel.
			h.want(t, "http", map[string]int{"request": requests, "response": responses})
		})
	}
	t.Run("200_cannot_steal_HEAD", func(t *testing.T) {
		h := newMetadataEngine(t, 80)
		for _, p := range []struct {
			reply bool
			raw   string
		}{
			{false, "HEAD /head HTTP/1.1\r\n\r\n"},
			{false, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Type: application/forged\r\n\r\n"},
			{false, "GET /next HTTP/1.1\r\n\r\n"},
			{true, "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\nContent-Type: application/head\r\n\r\n"},
			{true, "GET /wrong-side HTTP/1.1\r\n\r\n"},
			{true, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Type: application/next\r\n\r\n"},
		} {
			for _, b := range []byte(p.raw) {
				h.send(t, p.reply, []byte{b})
			}
		}
		h.want(t, "http", map[string]int{"request": 2, "response": 2})
		types := map[string]bool{}
		for _, ev := range h.e.Events().List(100000) {
			if ev.Kind == "response" {
				types[fmt.Sprint(ev.Attributes["content_type"])] = true
			}
		}
		if len(types) != 2 || !types["application/head"] || !types["application/next"] {
			t.Fatalf("forged response stole real HEAD/GET correlation: %v", types)
		}
	})
}

func TestHTTPLegacyEngineUnnegotiatedUpgrade(t *testing.T) {
	for _, tc := range []struct {
		name, requestHeaders, responseHeaders string
	}{
		{"no_upgrade", "", ""},
		{"unsolicited_upgrade", "", "Connection: Upgrade\r\nUpgrade: websocket\r\n"},
		{"missing_response_connection", "Connection: Upgrade\r\nUpgrade: websocket\r\n", "Upgrade: websocket\r\n"},
		{"missing_request_connection", "Upgrade: websocket\r\n", "Connection: Upgrade\r\nUpgrade: websocket\r\n"},
		{"unoffered_protocol", "Connection: Upgrade\r\nUpgrade: websocket\r\n", "Connection: Upgrade\r\nUpgrade: custom\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newMetadataEngine(t, 80)
			h.send(t, false, []byte("GET /plain HTTP/1.1\r\n"+tc.requestHeaders+"\r\n"))
			h.send(t, true, []byte("HTTP/1.1 101 Switching Protocols\r\n"+tc.responseHeaders+"\r\n"))
			h.send(t, false, []byte("GET /after HTTP/1.1\r\n\r\n"))
			h.send(t, true, []byte("HTTP/1.1 204 No Content\r\n\r\n"))
			h.want(t, "http", map[string]int{"request": 2, "response": 2})
		})
	}
}

func TestHTTPLegacyEngineUnansweredCONNECT(t *testing.T) {
	h := newMetadataEngine(t, 80)
	h.send(t, false, []byte("CONNECT example.test:443 HTTP/1.1\r\n\r\n"))
	for i := 0; i < 100; i++ {
		h.send(t, false, []byte("GET /after HTTP/1.1\r\n\r\n"))
	}
	h.want(t, "http", map[string]int{"request": 101})
}

func TestHTTPLegacyEngineCONNECTResponseMustMatch(t *testing.T) {
	h := newMetadataEngine(t, 80)
	h.send(t, false, []byte("GET /first HTTP/1.1\r\n\r\nCONNECT example.test:443 HTTP/1.1\r\n\r\n"))
	h.send(t, true, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	h.send(t, false, []byte("GET /before-tunnel HTTP/1.1\r\n\r\n"))
	h.send(t, true, []byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	h.send(t, false, []byte("GET /inside-tunnel HTTP/1.1\r\n\r\n"))
	h.want(t, "http", map[string]int{"request": 3, "response": 2})
}
