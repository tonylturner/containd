// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package ids_test

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	cpids "github.com/tonylturner/containd/pkg/cp/ids"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/itdpi"
)

func decodedProtocolEvent(t *testing.T, protocol string, payload []byte) dpi.Event {
	t.Helper()
	var decoder dpi.Decoder
	var port uint16
	transport, ipProtocol := "tcp", uint8(6)
	switch protocol {
	case "http":
		decoder, port = itdpi.NewHTTPDecoder(), 80
	case "dns":
		decoder, port = itdpi.NewDNSDecoder(), 53
		transport, ipProtocol = "udp", 17
	case "tls":
		decoder, port = itdpi.NewTLSDecoder(), 443
	default:
		t.Fatalf("unknown test protocol %q", protocol)
	}
	state := flow.NewState(flow.Key{
		SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"),
		SrcPort: 12345, DstPort: port, Proto: ipProtocol,
	}, time.Unix(1, 0))
	if !decoder.Supports(state) {
		t.Fatal("decoder does not support test flow")
	}
	events, err := decoder.OnPacket(state, &dpi.ParsedPacket{
		Proto: transport, SrcPort: 12345, DstPort: port, Payload: payload,
	})
	if err != nil || len(events) != 1 {
		t.Fatalf("decode: %d events, error %v", len(events), err)
	}
	if events[0].Proto != protocol {
		t.Fatalf("unexpected decoder event: %+v", events[0])
	}
	return events[0]
}

func dnsQuery(name string) []byte {
	// RFC 1035: ID, RD, QDCOUNT=1, no answers/authority/additional records.
	wire := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	return append(wire, 0, 0, 1, 0, 1) // root, QTYPE=A, QCLASS=IN
}

func tlsClientHello(name string) []byte {
	// RFC 5246 ClientHello with one cipher suite and RFC 6066 host_name SNI.
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0, 0x2f, 1, 0) // no session; one suite; null compression
	serverName := binary.BigEndian.AppendUint16(nil, uint16(3+len(name)))
	serverName = append(serverName, 0)
	serverName = binary.BigEndian.AppendUint16(serverName, uint16(len(name)))
	serverName = append(serverName, name...)
	extension := binary.BigEndian.AppendUint16([]byte{0, 0}, uint16(len(serverName)))
	extension = append(extension, serverName...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(extension)))
	body = append(body, extension...)
	handshake := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	record := binary.BigEndian.AppendUint16([]byte{0x16, 3, 1}, uint16(len(handshake)))
	return append(record, handshake...)
}

func TestImportedPacketRulesMatchDecoderEvents(t *testing.T) {
	for _, format := range []string{"suricata", "snort"} {
		for _, tt := range []struct {
			keywords, proto, field, pattern string
			matching, unrelated             []byte
		}{
			{"http_uri http.uri", "http", "path", "/bad",
				[]byte("GET /bad?x=1 HTTP/1.1\r\nHost: example.test\r\n\r\n"),
				[]byte("GET /safe HTTP/1.1\r\nHost: bad.test\r\n\r\n")},
			// Content searches a method buffer; it is not whole-method equality.
			{"http_method http.method", "http", "method", "GE",
				[]byte("GET /safe HTTP/1.1\r\nHost: example.test\r\n\r\n"),
				[]byte("POST /GE HTTP/1.1\r\nHost: example.test\r\n\r\n")},
			{"dns_query dns.query", "dns", "qname", "bad.test",
				dnsQuery("bad.test"), dnsQuery("safe.test")},
			{"tls_sni tls.sni", "tls", "sni", "bad.test",
				tlsClientHello("bad.test"), tlsClientHello("safe.test")},
		} {
			for _, keyword := range strings.Fields(tt.keywords) {
				t.Run(format+"/"+keyword, func(t *testing.T) {
					source := `alert ` + tt.proto + ` any any -> any any (msg:"decoder match"; sid:1; rev:1; classtype:misc-activity; priority:2; reference:url,example.test; metadata:deployment test; content:"` + tt.pattern + `"; ` + keyword + `;)`
					parsed, err := cpids.ImportRules([]byte(source), format)
					if err != nil {
						t.Fatal(err)
					}
					if parsed[0].When.Field != "attr."+tt.field || parsed[0].When.Op != "contains" {
						t.Fatalf("wrong mapped predicate: %+v", parsed[0].When)
					}
					evaluator := compiledImport(t, format, source, nil)
					for _, sample := range []struct {
						wire   []byte
						alerts int
					}{{tt.matching, 1}, {tt.unrelated, 0}} {
						ev := decodedProtocolEvent(t, tt.proto, sample.wire)
						if _, emitted := ev.Attributes[tt.field]; !emitted {
							t.Fatalf("decoder did not emit %q", tt.field)
						}
						if got := len(evaluator.Evaluate(ev)); got != sample.alerts {
							t.Fatalf("got %d alerts, want %d; decoded %+v", got, sample.alerts, ev)
						}
					}
				})
			}
		}
	}
}

func TestImportedHeaderBufferIsNotEvaluable(t *testing.T) {
	wire := []byte("GET /safe HTTP/1.1\r\nHost: bad.test\r\nUser-Agent: bad-agent\r\nX-Hidden: bad\r\n\r\n")
	ev := decodedProtocolEvent(t, "http", wire)
	for _, format := range []string{"suricata", "snort"} {
		for _, keyword := range []string{"http_header", "http.header"} {
			t.Run(format+"/"+keyword, func(t *testing.T) {
				source := `alert http any any -> any any (msg:"header"; sid:1; content:"bad"; ` + keyword + `;)`
				evaluator := compiledImport(t, format, source, []string{keyword})
				if alerts := evaluator.Evaluate(ev); len(alerts) != 0 {
					t.Fatal("a subset of exposed headers was mistaken for the header buffer")
				}
			})
		}
	}
}

func TestImportedSigmaFieldsMatchDecoderEvents(t *testing.T) {
	for _, tt := range []struct {
		fields, proto, value string
		matching, unrelated  []byte
	}{
		{"http_uri attr.http_uri path attr.path", "http", "/bad",
			[]byte("GET /bad HTTP/1.1\r\nHost: example.test\r\n\r\n"),
			[]byte("GET /safe HTTP/1.1\r\nHost: example.test\r\n\r\n")},
		{"http_method attr.http_method method", "http", "GET",
			[]byte("GET /safe HTTP/1.1\r\nHost: example.test\r\n\r\n"),
			[]byte("POST /GET HTTP/1.1\r\nHost: example.test\r\n\r\n")},
		{"http_host host", "http", "bad.test",
			[]byte("GET /safe HTTP/1.1\r\nHost: bad.test\r\n\r\n"),
			[]byte("GET /safe HTTP/1.1\r\nHost: safe.test\r\n\r\n")},
		{"http_user_agent user_agent", "http", "bad-agent",
			[]byte("GET /safe HTTP/1.1\r\nUser-Agent: bad-agent\r\n\r\n"),
			[]byte("GET /safe HTTP/1.1\r\nUser-Agent: safe-agent\r\n\r\n")},
		{"dns_query attr.dns_query qname", "dns", "bad.test",
			dnsQuery("bad.test"), dnsQuery("safe.test")},
		{"tls_sni attr.tls_sni sni", "tls", "bad.test",
			tlsClientHello("bad.test"), tlsClientHello("safe.test")},
	} {
		for _, field := range strings.Fields(tt.fields) {
			t.Run(field, func(t *testing.T) {
				source := "title: Decoder field\ndetection:\n  selection:\n    " + field + ": " + tt.value + "\n  condition: selection\n"
				evaluator := compiledImport(t, "sigma", source, nil)
				for _, sample := range []struct {
					wire   []byte
					alerts int
				}{{tt.matching, 1}, {tt.unrelated, 0}} {
					ev := decodedProtocolEvent(t, tt.proto, sample.wire)
					if got := len(evaluator.Evaluate(ev)); got != sample.alerts {
						t.Fatalf("got %d alerts, want %d; decoded %+v", got, sample.alerts, ev)
					}
				}
			})
		}
	}
}

func TestImportedSigmaPortsMatchDecoderEvents(t *testing.T) {
	ev := decodedProtocolEvent(t, "http", []byte("GET /safe HTTP/1.1\r\nHost: example.test\r\n\r\n"))
	for _, tt := range []struct {
		field, value string
		alerts       int
	}{
		{"srcport", "12345", 1}, {"attr.srcport", "12345", 1}, {"src_port", "12345", 1},
		{"dstport", "80", 1}, {"attr.dstport", "80", 1}, {"dst_port", "80", 1},
		{"srcport", "54321", 0}, {"dstport", "8080", 0},
	} {
		t.Run(tt.field+"/"+tt.value, func(t *testing.T) {
			source := "title: Port field\ndetection:\n  selection:\n    " + tt.field + ": " + tt.value + "\n  condition: selection\n"
			evaluator := compiledImport(t, "sigma", source, nil)
			if got := len(evaluator.Evaluate(ev)); got != tt.alerts {
				t.Fatalf("got %d alerts, want %d", got, tt.alerts)
			}
		})
	}
}

func TestImportedSigmaUnknownFieldsAreNotEvaluable(t *testing.T) {
	ev := decodedProtocolEvent(t, "http", []byte("GET /bad HTTP/1.1\r\nHost: bad.test\r\n\r\n"))
	for _, field := range []string{
		"http_header", "attr.http_header", "srcip", "dstip", "src_ip", "dst_ip", "ImaginaryField", "attr.unknown",
		"cipher_suites", "extensions", "requested_protocols",
	} {
		t.Run(field, func(t *testing.T) {
			for _, condition := range []string{"selection", "not selection"} {
				source := "title: Missing field\ndetection:\n  selection:\n    " + field + ": bad\n  condition: " + condition + "\n"
				evaluator := compiledImport(t, "sigma", source, []string{field})
				if alerts := evaluator.Evaluate(ev); len(alerts) != 0 {
					t.Fatal("missing field produced an alert")
				}
			}
		})
	}
}
