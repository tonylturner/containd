// SPDX-License-Identifier: Apache-2.0

package itdpi

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"golang.org/x/net/http2/hpack"
)

func h2Frame(typ, flags byte, id uint32, p []byte) []byte {
	b := []byte{byte(len(p) >> 16), byte(len(p) >> 8), byte(len(p)), typ, flags, byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)}
	return append(b, p...)
}
func h2Settings() []byte { return h2Frame(4, 0, 0, nil) }
func h2Headers(fields ...hpack.HeaderField) []byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, f := range fields {
		if err := enc.WriteField(f); err != nil {
			panic(err)
		}
	}
	return buf.Bytes()
}
func h2RequestBlock() []byte {
	return h2Headers(hpack.HeaderField{Name: ":method", Value: "POST"}, hpack.HeaderField{Name: ":scheme", Value: "http"}, hpack.HeaderField{Name: ":path", Value: "/api"}, hpack.HeaderField{Name: ":authority", Value: "example.test"}, hpack.HeaderField{Name: "content-type", Value: "application/json"}, hpack.HeaderField{Name: "authorization", Value: "SECRET"})
}

func inspectHTTPChunks(t *testing.T, raw []byte, split int, dir dpi.StreamDir) []dpi.Event {
	t.Helper()
	mgr := dpi.NewManager(NewHTTPDecoder())
	st := httpFlowState(12345, 80)
	if dir == dpi.ServerToClient {
		st = httpFlowState(80, 12345)
	}
	var events []dpi.Event
	for i, p := range [][]byte{raw[:split], raw[split:]} {
		off := int64(0)
		if i == 1 {
			off = int64(split)
		}
		pkt := &dpi.ParsedPacket{Payload: p, Proto: "tcp", HasOffset: true, Session: "h2", Dir: dir, Offset: off}
		res := mgr.Inspect(st, pkt)
		if res.Err != nil {
			t.Fatalf("split %d: %v", split, res.Err)
		}
		events = append(events, res.Events...)
		// A retransmission must not re-decode a header block or mutate HPACK.
		again := mgr.Inspect(st, pkt)
		if again.Err != nil || len(again.Events) != 0 {
			t.Fatalf("retransmission: %+v", again)
		}
	}
	mgr.EndStream("h2")
	return events
}

func TestHTTP2StreamsSplitAndCoalesced(t *testing.T) {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	var blocks [][]byte
	for _, path := range []string{"/api/one", "/api/two"} {
		buf.Reset()
		for _, f := range []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "http"}, {Name: ":path", Value: path}, {Name: ":authority", Value: "example.test"}, {Name: "content-type", Value: "application/json"}, {Name: "authorization", Value: "SECRET"}} {
			if err := enc.WriteField(f); err != nil {
				t.Fatal(err)
			}
		}
		blocks = append(blocks, append([]byte(nil), buf.Bytes()...))
	}
	raw := append([]byte(h2Preface), h2Settings()...)
	raw = append(raw, h2Frame(1, 0, 1, blocks[0][:5])...)
	raw = append(raw, h2Frame(9, 4, 1, blocks[0][5:])...)
	raw = append(raw, h2Frame(0, 1, 1, []byte("BODY_SECRET"))...)
	raw = append(raw, h2Frame(1, 5, 3, blocks[1])...)
	for split := 0; split <= len(raw); split++ {
		events := inspectHTTPChunks(t, raw, split, dpi.ClientToServer)
		if len(events) != 3 || events[0].Kind != "preface" {
			t.Fatalf("split %d: %+v", split, events)
		}
		for i, ev := range events[1:] {
			a := ev.Attributes
			if ev.Proto != "http2" || ev.Kind != "request" || a["stream_id"] != uint32(1+2*i) || a["method"] != "POST" || a["authority"] != "example.test" || a["content_type"] != "application/json" || a["path"] != []string{"/api/one", "/api/two"}[i] {
				t.Fatalf("split %d: %+v", split, ev)
			}
			for k, v := range a {
				if strings.Contains(k, "authorization") || strings.Contains(k, "preview") || strings.Contains(k, "hash") {
					t.Fatalf("private field %s", k)
				}
				if str, ok := v.(string); ok && strings.Contains(str, "SECRET") {
					t.Fatalf("private value %s", str)
				}
			}
		}
	}
}

func TestHTTP2Response(t *testing.T) {
	block := h2Headers(hpack.HeaderField{Name: ":status", Value: "201"}, hpack.HeaderField{Name: "content-type", Value: "application/problem+json"})
	raw := append(h2Settings(), h2Frame(1, 5, 3, block)...)
	for split := 0; split <= len(raw); split++ {
		events := inspectHTTPChunks(t, raw, split, dpi.ServerToClient)
		if len(events) != 1 || events[0].Kind != "response" || events[0].Attributes["status"] != "201" || events[0].Attributes["content_type"] != "application/problem+json" || events[0].Attributes["stream_id"] != uint32(3) {
			t.Fatalf("split %d: %v", split, events)
		}
	}
}

func TestHTTP2RFC7541Requests(t *testing.T) {
	// RFC 7541 C.3.1 and C.4.1: the same request without/with Huffman coding.
	for _, wire := range []string{"828684410f7777772e6578616d706c652e636f6d", "828684418cf1e3c2e5f23a6ba0ab90f4ff"} {
		block, err := hex.DecodeString(wire)
		if err != nil {
			t.Fatal(err)
		}
		raw := append([]byte(h2Preface), h2Settings()...)
		raw = append(raw, h2Frame(1, 5, 1, block)...)
		events := inspectHTTPChunks(t, raw, 7, dpi.ClientToServer)
		if len(events) != 2 || events[1].Attributes["authority"] != "www.example.com" || events[1].Attributes["method"] != "GET" || events[1].Attributes["path"] != "/" {
			t.Fatal(events)
		}
	}
}

func TestHTTP2BoundsAndMalformed(t *testing.T) {
	hugeHeader := h2Headers(hpack.HeaderField{Name: ":status", Value: "200"}, hpack.HeaderField{Name: "x-long", Value: strings.Repeat("a", maxHTTPHeaders+1)})
	bigList := []byte{0x88}
	bigList = append(bigList, bytes.Repeat([]byte{0x90}, 1000)...) // indexed accept-encoding, expanded list >32KiB
	cases := map[string][]byte{
		"oversized frame":           {1, 0, 0, 1, 4, 0, 0, 0, 1},
		"bad settings":              h2Frame(4, 0, 0, []byte{0}),
		"bad settings value":        h2Frame(4, 0, 0, []byte{0, 2, 0, 0, 0, 2}),
		"zero stream":               h2Frame(1, 4, 0, []byte{0x88}),
		"unexpected continuation":   h2Frame(9, 4, 1, []byte{0x88}),
		"interleaved block":         append(h2Frame(1, 0, 1, []byte{0x88}), h2Frame(0, 0, 1, nil)...),
		"wrong continuation stream": append(h2Frame(1, 0, 1, []byte{0x88}), h2Frame(9, 4, 3, nil)...),
		"invalid hpack index":       h2Frame(1, 4, 1, []byte{0xff, 0xff, 0x7f}),
		"incomplete hpack":          h2Frame(1, 4, 1, []byte{0x40}),
		"dynamic table size":        h2Frame(1, 4, 1, []byte{0x3f, 0xe2, 0x1f}), // 4097, over ceiling
		"header list":               h2Frame(1, 4, 1, bigList),
		"pseudo after regular":      h2Frame(1, 4, 1, h2Headers(hpack.HeaderField{Name: "content-type", Value: "text/plain"}, hpack.HeaderField{Name: ":status", Value: "200"})),
		"bad padding":               h2Frame(1, 12, 1, []byte{4}),
		"short ping":                h2Frame(6, 0, 0, []byte{1}),
	}
	// Split the huge string over legal-size frames to reach the HPACK bound.
	var long []byte
	for len(hugeHeader) > 0 {
		n := min(len(hugeHeader), maxH2Frame)
		typ := byte(9)
		if len(long) == 0 {
			typ = 1
		}
		flags := byte(0)
		if n == len(hugeHeader) {
			flags = 4
		}
		long = append(long, h2Frame(typ, flags, 1, hugeHeader[:n])...)
		hugeHeader = hugeHeader[n:]
	}
	cases["header string"] = long
	var compressed []byte
	for i := 0; i < 5; i++ {
		typ := byte(9)
		if i == 0 {
			typ = 1
		}
		compressed = append(compressed, h2Frame(typ, 0, 1, bytes.Repeat([]byte{0x88}, maxH2Frame))...)
	}
	cases["compressed block"] = compressed
	for name, frames := range cases {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte(h2Preface), h2Settings()...)
			raw = append(raw, frames...)
			d := NewHTTPDecoder()
			r, err := d.ParseStream(httpFlowState(1, 80), dpi.StreamView{Session: "bad", Bytes: raw})
			if err != nil || r.Consumed != len(raw) || len(r.Frames) == 0 || len(r.Frames[len(r.Frames)-1].Events) != 1 || r.Frames[len(r.Frames)-1].Events[0].Kind != "malformed" {
				t.Fatalf("missing terminal malformed event: %+v %v", r, err)
			}
			again, err := d.ParseStream(httpFlowState(1, 80), dpi.StreamView{Session: "bad", Base: int64(len(raw)), Bytes: raw})
			if err != nil || len(again.Frames) != 1 || len(again.Frames[0].Events) != 0 {
				t.Fatalf("restarted malformed stream: %+v %v", again, err)
			}
			d.StreamEnded("bad", dpi.DirUnknown)
			if len(d.streams) != 0 {
				t.Fatal("stream state leaked")
			}
		})
	}
	// An incomplete frame is retained, not called malformed or emitted early.
	raw := append([]byte(h2Preface), h2Settings()...)
	raw = append(raw, h2Frame(1, 4, 1, h2RequestBlock())...)
	for n := len(h2Preface) + 9 + 1; n < len(raw); n++ {
		r, err := NewHTTPDecoder().ParseStream(httpFlowState(1, 80), dpi.StreamView{Bytes: raw[:n]})
		if err != nil || !r.NeedMore || len(r.Frames) != 2 {
			t.Fatalf("truncated %d: %+v %v", n, r, err)
		}
	}
}

func TestHTTP2UpgradeAndBodyFraming(t *testing.T) {
	request := "POST / HTTP/1.1\r\nHost: example.test\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: \r\nContent-Length: 4\r\nContent-Type: text/plain\r\n\r\nBODY"
	raw := append([]byte(request+h2Preface), h2Settings()...)
	raw = append(raw, h2Frame(1, 5, 3, h2RequestBlock())...)
	for split := 0; split <= len(raw); split++ {
		events := inspectHTTPChunks(t, raw, split, dpi.ClientToServer)
		if len(events) != 3 || events[0].Proto != "http" || events[0].Attributes["content_type"] != "text/plain" || events[2].Attributes["stream_id"] != uint32(3) {
			t.Fatal(events)
		}
	}
	response := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"
	raw = append([]byte(response), h2Settings()...)
	raw = append(raw, h2Frame(1, 5, 1, []byte{0x88})...)
	events := inspectHTTPChunks(t, raw, 11, dpi.ServerToClient)
	if len(events) != 2 || events[1].Attributes["status"] != "200" || events[1].Attributes["stream_id"] != uint32(1) {
		t.Fatal(events)
	}
	// Chunk bodies containing request-like text must not become new requests.
	chunked := []byte("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n10\r\nGET / HTTP/1.1\r\n\r\n0\r\nX-Trailer: yes\r\n\r\nGET /next HTTP/1.1\r\n\r\n")
	for split := 0; split <= len(chunked); split++ {
		events := inspectHTTPChunks(t, chunked, split, dpi.ClientToServer)
		if len(events) != 2 || events[1].Attributes["path"] != "/next" {
			t.Fatal(events)
		}
	}
}

func TestHTTP2PushAndTrailersPreserveCompression(t *testing.T) {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, f := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":path", Value: "/"}, {Name: ":authority", Value: "push.example.test"}} {
		if err := enc.WriteField(f); err != nil {
			t.Fatal(err)
		}
	}
	promise := append([]byte{0, 0, 0, 2}, buf.Bytes()...)
	raw := append(h2Settings(), h2Frame(5, 4, 1, promise)...)
	buf.Reset()
	for _, f := range []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-type", Value: "text/plain"}} {
		if err := enc.WriteField(f); err != nil {
			t.Fatal(err)
		}
	}
	raw = append(raw, h2Frame(1, 4, 2, buf.Bytes())...)
	buf.Reset()
	if err := enc.WriteField(hpack.HeaderField{Name: "x-trailer", Value: "yes"}); err != nil {
		t.Fatal(err)
	}
	raw = append(raw, h2Frame(1, 5, 2, buf.Bytes())...)
	events := inspectHTTPChunks(t, raw, 10, dpi.ServerToClient)
	if len(events) != 1 || events[0].Attributes["stream_id"] != uint32(2) || events[0].Kind != "response" {
		t.Fatal(events)
	}
}

func TestHTTPBodyFramingBounds(t *testing.T) {
	for _, raw := range []string{
		"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
		"POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
		"POST / HTTP/1.1\r\nContent-Length: bad\r\n\r\n",
		"POST / HTTP/1.1\r\n Transfer-Encoding: chunked\r\n\r\n",
		"GET / HTTP/1.1\r\nX-Long: " + strings.Repeat("a", maxHTTPHeaders) + "\r\n\r\n",
	} {
		events, err := NewHTTPDecoder().OnPacket(httpFlowState(1, 80), &dpi.ParsedPacket{Payload: []byte(raw), Proto: "tcp"})
		if err != nil || len(events) != 1 || events[0].Kind != "malformed" {
			t.Fatalf("missing malformed event: %v %v", events, err)
		}
	}
	raw := []byte("HTTP/1.1 304 Not Modified\r\nContent-Length: 123\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n")
	events := inspectHTTPChunks(t, raw, 7, dpi.ServerToClient)
	if len(events) != 2 || events[1].Attributes["content_type"] != "text/plain" {
		t.Fatal(events)
	}
}
