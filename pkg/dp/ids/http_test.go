// SPDX-License-Identifier: Apache-2.0

package ids

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/itdpi"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestHTTPContentTypeConditions(t *testing.T) {
	var h2 bytes.Buffer
	enc := hpack.NewEncoder(&h2)
	for _, f := range []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: "example.test"}, {Name: ":path", Value: "/"}, {Name: "content-type", Value: "application/json; charset=utf-8"}} {
		if err := enc.WriteField(f); err != nil {
			t.Fatal(err)
		}
	}
	var wire bytes.Buffer
	wire.WriteString(http2.ClientPreface)
	framer := http2.NewFramer(&wire, nil)
	if err := framer.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: h2.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	var responseWire bytes.Buffer
	responseFramer := http2.NewFramer(&responseWire, nil)
	if err := responseFramer.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	h2.Reset()
	responseEncoder := hpack.NewEncoder(&h2)
	for _, field := range []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "content-type", Value: "application/json; charset=utf-8"}} {
		if err := responseEncoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := responseFramer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: h2.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"request":        []byte("POST / HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 0\r\n\r\n"),
		"response":       []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 0\r\n\r\n"),
		"http2":          wire.Bytes(),
		"http2 response": responseWire.Bytes(),
	} {
		t.Run(name, func(t *testing.T) {
			st := flow.NewState(flow.Key{SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2), SrcPort: 12345, DstPort: 80, Proto: 6}, time.Now())
			events, err := itdpi.NewHTTPDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: raw, Proto: "tcp", SrcPort: 12345, DstPort: 80})
			if err != nil {
				t.Fatal(err)
			}
			ev := events[len(events)-1]
			for _, field := range []string{"attr.content_type", "content_type"} {
				r := rules.IDSRule{ID: "json", Proto: ev.Proto, Kind: ev.Kind, When: rules.IDSCondition{Field: field, Op: "contains", Value: "application/json"}}
				e := New(rules.IDSConfig{Enabled: true, Rules: []rules.IDSRule{r}})
				if alerts := e.Evaluate(ev); len(alerts) != 1 {
					t.Fatalf("%s: no content type alert for %+v", field, ev)
				}
				ev.Attributes["content_type"] = "text/plain"
				if len(e.Evaluate(ev)) != 0 {
					t.Fatal("wrong content type matched")
				}
				delete(ev.Attributes, "content_type")
				if len(e.Evaluate(ev)) != 0 {
					t.Fatal("absent content type matched")
				}
				ev.Attributes["content_type"] = "application/json; charset=utf-8"
			}
		})
	}
}
