// SPDX-License-Identifier: Apache-2.0

package itdpi

import (
	"fmt"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestHTTPLineEndingsAndLeadingEmptyLines(t *testing.T) {
	for _, nl := range []string{"\n", "\r\n"} {
		raw := []byte(nl + nl + "POST /submit HTTP/1.1" + nl + "Host: example.test" + nl + "Content-Type: application/json" + nl + "Content-Length: 0" + nl + nl)
		for split := 0; split <= len(raw); split++ {
			events := inspectHTTPChunks(t, raw, split, dpi.ClientToServer)
			if len(events) != 1 || events[0].Kind != "request" || events[0].Attributes["content_type"] != "application/json" {
				t.Fatalf("split %d: %v", split, events)
			}
		}
	}
}

func TestHTTPMethodCorrelationBoundAndCleanup(t *testing.T) {
	d := NewHTTPDecoder()
	st := httpFlowState(12345, 80)
	req := []byte("GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
	const requests = 10000
	for i := 0; i < requests; i++ {
		r, err := d.ParseStream(st, dpi.StreamView{Session: "bounded", Dir: dpi.ClientToServer, Base: int64(i * len(req)), Bytes: req})
		if err != nil || len(r.Frames) != 1 || len(r.Frames[0].Events) != 1 {
			t.Fatalf("request %d: %+v %v", i, r, err)
		}
		if r.Frames[0].Events[0].Kind != "request" {
			t.Fatal(r)
		}
	}
	s := d.streams[httpStreamKey{"bounded", dpi.ClientToServer}]
	if len(s.peer.methods) != maxHTTPRequestMethods || cap(s.peer.methods) > 128 ||
		s.peer.dropped != requests-maxHTTPRequestMethods || s.resync {
		t.Fatalf("queue overflow lost coverage or its bound: %+v", s.peer)
	}
	if s.peer.pending().method != "GET" {
		t.Fatal("overflow discarded the known FIFO prefix")
	}
	reply := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	server := httpFlowState(80, 12345)
	for i := 0; i < requests; i++ {
		r, err := d.ParseStream(server, dpi.StreamView{Session: "bounded", Dir: dpi.ServerToClient, Base: int64(i * len(reply)), Bytes: reply})
		if err != nil || len(r.Frames) != 1 || len(r.Frames[0].Events) != 1 || r.Frames[0].Events[0].Kind != "response" {
			t.Fatalf("reply %d: %+v %v", i, r, err)
		}
	}
	if len(s.peer.methods) != 0 || s.peer.dropped != 0 {
		t.Fatal("correlation failed to recover after draining replies")
	}
	d.StreamEnded("bounded", dpi.ClientToServer)
	d.StreamEnded("bounded", dpi.ServerToClient)
	if len(d.streams) != 0 || len(d.connections) != 0 {
		t.Fatal("connection state leaked")
	}
}

func TestHTTPMethodCorrelationAcrossDirections(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy_%v", legacy), func(t *testing.T) {
			d := NewHTTPDecoder()
			mgr := dpi.NewManager(d)
			client := httpFlowState(12345, 80)
			server := httpFlowState(80, 12345)
			server.Key.SrcIP, server.Key.DstIP = client.Key.DstIP, client.Key.SrcIP
			requests := "HEAD /head HTTP/1.1\r\n\r\nGET /next HTTP/1.1\r\n\r\nGET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n"
			responses := "HTTP/1.1 103 Early Hints\r\nContent-Length: 4096\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\nHTTP/1.1 204 No Content\r\nContent-Length: 4096\r\n\r\nHTTP/1.1 304 Not Modified\r\nContent-Length: 4096\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok"
			for i, raw := range []string{requests, responses} {
				st := client
				dir := dpi.ClientToServer
				if i == 1 {
					st = server
					dir = dpi.ServerToClient
				}
				if legacy {
					dir = dpi.DirUnknown
				}
				var events []dpi.Event
				// One-byte deliveries exercise cross-direction state and bounded header scans.
				for off, b := range []byte(raw) {
					r := mgr.Inspect(st, &dpi.ParsedPacket{Proto: "tcp", Payload: []byte{b}, HasOffset: !legacy, Session: "pair", Dir: dir, Offset: int64(off), TCPSeqValid: legacy, TCPSeq: uint32(100 + off)})
					if r.Err != nil {
						t.Fatal(r.Err)
					}
					events = append(events, r.Events...)
				}
				want := 4
				if i == 1 {
					want = 5
				}
				if len(events) != want {
					t.Fatalf("direction %d: %v", i, events)
				}
				if i == 1 && events[4].Attributes["content_type"] != "text/plain" {
					t.Fatal(events)
				}
			}
			if legacy {
				_, _ = mgr.OnFlowEnd(client)
				_, _ = mgr.OnFlowEnd(server)
			} else {
				mgr.EndStream("pair")
			}
			if len(d.streams) != 0 || len(d.connections) != 0 {
				t.Fatal("connection state leaked")
			}
		})
	}
}

func TestHTTPUnanchoredAndTerminalStreams(t *testing.T) {
	for _, anchored := range []bool{false, true} {
		mgr := dpi.NewManager(NewHTTPDecoder())
		st := httpFlowState(12345, 80)
		seq := uint32(100)
		if anchored {
			raw := []byte("GET / HTTP/1.1\r\n\r\n")
			r := mgr.Inspect(st, &dpi.ParsedPacket{Proto: "tcp", Payload: raw, TCPSeqValid: true, TCPSeq: seq})
			seq += uint32(len(raw))
			if len(r.Events) != 1 {
				t.Fatal(r)
			}
		}
		count := 0
		garbage := []byte(strings.Repeat("x", 1400) + "\r\n\r\n")
		for i := 0; i < 100; i++ {
			r := mgr.Inspect(st, &dpi.ParsedPacket{Proto: "tcp", Payload: garbage, TCPSeqValid: true, TCPSeq: seq})
			seq += uint32(len(garbage))
			if r.Err != nil {
				t.Fatal(r.Err)
			}
			for _, e := range r.Events {
				if e.Kind != "malformed" {
					t.Fatal(e)
				}
				count++
			}
		}
		want := 0
		if anchored {
			want = 1
		}
		if count != want {
			t.Fatalf("got %d malformed want %d", count, want)
		}
		// A stream end removes the terminal state; the next incarnation can decode.
		_, _ = mgr.OnFlowEnd(st)
		r := mgr.Inspect(st, &dpi.ParsedPacket{Proto: "tcp", Payload: []byte("GET /new HTTP/1.1\r\n\r\n"), TCPSeqValid: true, TCPSeq: seq})
		if len(r.Events) != 1 || r.Events[0].Kind != "request" {
			t.Fatal(r)
		}
	}
}

func TestHTTPRejectedCONNECTRemainsHTTP(t *testing.T) {
	mgr := dpi.NewManager(NewHTTPDecoder())
	client := httpFlowState(12345, 80)
	server := httpFlowState(80, 12345)
	server.Key.SrcIP, server.Key.DstIP = client.Key.DstIP, client.Key.SrcIP
	request := []byte("CONNECT example.test:443 HTTP/1.1\r\n\r\n")
	for _, p := range []struct {
		reply bool
		seq   uint32
		raw   []byte
		kind  string
	}{
		{false, 100, request, "request"},
		{true, 200, []byte("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"), "response"},
		{false, uint32(100 + len(request)), []byte("GET /retry HTTP/1.1\r\n\r\n"), "request"},
	} {
		st := client
		if p.reply {
			st = server
		}
		r := mgr.Inspect(st, &dpi.ParsedPacket{Proto: "tcp", Payload: p.raw, TCPSeqValid: true, TCPSeq: p.seq})
		if r.Err != nil || len(r.Events) != 1 || r.Events[0].Kind != p.kind {
			t.Fatal(r)
		}
	}
}

func TestHTTPBareLFChunkedBody(t *testing.T) {
	raw := []byte("POST / HTTP/1.1\nTransfer-Encoding: chunked\n\n1\nx\n0\n\nGET /next HTTP/1.1\n\n")
	for split := 0; split <= len(raw); split++ {
		events := inspectHTTPChunks(t, raw, split, dpi.ClientToServer)
		if len(events) != 2 || events[1].Attributes["path"] != "/next" {
			t.Fatalf("split %d: %v", split, events)
		}
	}
}
