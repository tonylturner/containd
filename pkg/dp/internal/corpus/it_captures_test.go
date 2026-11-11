// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package corpus_test

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/internal/corpus"
	"github.com/tonylturner/containd/pkg/dp/itdpi"
)

type itCaptureEntry struct {
	Protocol string `json:"protocol"`
	PCAP     string `json:"pcap"`
	Frames   int    `json:"frames"`
	Shows    string `json:"shows"`
}

type itCaptureManifest struct {
	Version  int              `json:"version"`
	Captures []itCaptureEntry `json:"captures"`
}

type itExpectation struct {
	label    string
	proto    string
	kind     string
	key      string
	value    string
	count    int
	gap      bool
	contains bool
}

type itDecoderCase struct {
	protocol string
	port     uint16
	decoder  func() dpi.Decoder
	wants    []itExpectation
}

type itObservedEvent struct {
	frame int
	event dpi.Event
}

var itDecoderCases = []itDecoderCase{
	{
		protocol: "dns",
		port:     53,
		decoder:  func() dpi.Decoder { return itdpi.NewDNSDecoder() },
		wants: []itExpectation{
			{label: "A query www.example.test", proto: "dns", kind: "query", key: "qname", value: "www.example.test", count: 1},
			{label: "AAAA query www.example.test", proto: "dns", kind: "query", key: "qtype", value: "28", count: 1},
			{label: "TXT query www.example.test", proto: "dns", kind: "query", key: "qtype", value: "16", count: 1},
			{label: "NXDOMAIN response", proto: "dns", kind: "response", key: "rcode", value: "3", count: 1},
		},
	},
	{
		protocol: "tls",
		port:     443,
		decoder:  func() dpi.Decoder { return itdpi.NewTLSDecoder() },
		wants: []itExpectation{
			{label: "TLS 1.2 ClientHello SNI", proto: "tls", kind: "client_hello", key: "sni", value: "tls12.example.test", count: 1},
			{label: "TLS 1.2 ClientHello ALPN", proto: "tls", kind: "client_hello", key: "alpn", value: "h2", count: 1},
			{label: "TLS 1.3 ClientHello SNI", proto: "tls", kind: "client_hello", key: "sni", value: "tls13.example.test", count: 1},
			{label: "TLS 1.3 ClientHello ALPN", proto: "tls", kind: "client_hello", key: "alpn", value: "http/1.1", count: 1},
			{label: "TLS 1.3 protocol version", proto: "tls", kind: "client_hello", key: "tls_version", value: "TLS1.3", count: 1, gap: true},
		},
	},
	{
		protocol: "http",
		port:     80,
		decoder:  func() dpi.Decoder { return itdpi.NewHTTPDecoder() },
		wants: []itExpectation{
			{label: "HTTP GET request", proto: "http", kind: "request", key: "method", value: "GET", count: 1},
			{label: "HTTP POST request", proto: "http", kind: "request", key: "method", value: "POST", count: 1},
			{label: "HTTP Host", proto: "http", kind: "request", key: "host", value: "www.example.test", count: 2},
			{label: "HTTP User-Agent", proto: "http", kind: "request", key: "user_agent", value: "containd-it-capture/1.0", count: 2},
			{label: "HTTP POST Content-Type", proto: "http", kind: "request", key: "content_type", value: "application/json", count: 1, gap: true},
		},
	},
	{
		protocol: "ssh",
		port:     22,
		decoder:  func() dpi.Decoder { return itdpi.NewSSHDecoder() },
		wants: []itExpectation{
			{label: "SSH version exchange", proto: "ssh", kind: "version_exchange", key: "software", value: "OpenSSH_9.2p1", count: 1},
			{label: "SSH key exchange init", proto: "ssh", kind: "kex_init", key: "kex_algorithm", value: "sntrup761x25519-sha512", count: 1},
		},
	},
	{
		protocol: "ntp",
		port:     123,
		decoder:  func() dpi.Decoder { return itdpi.NewNTPDecoder() },
		wants: []itExpectation{
			{label: "NTP client request", proto: "ntp", kind: "request", key: "mode_name", value: "client", count: 1},
			{label: "NTP server response", proto: "ntp", kind: "response", key: "mode_name", value: "server", count: 1},
		},
	},
	{
		protocol: "snmp",
		port:     161,
		decoder:  func() dpi.Decoder { return itdpi.NewSNMPDecoder() },
		wants: []itExpectation{
			{label: "SNMPv2c community", proto: "snmp", kind: "get_request", key: "community", value: "public", count: 1},
			{label: "SNMPv2c Get request OIDs", proto: "snmp", kind: "get_request", key: "oids", value: "1.3.6.1.2.1.1.1.0", count: 1, contains: true},
			{label: "SNMP community response", proto: "snmp", kind: "get_response", key: "community", value: "public", count: 1},
			{label: "SNMP Get response OIDs", proto: "snmp", kind: "get_response", key: "oids", value: "1.3.6.1.2.1.1.1.0", count: 1, contains: true},
			{label: "SNMPv2c GetNext community", proto: "snmp", kind: "get_next_request", key: "community", value: "public", count: 1},
			{label: "SNMPv2c GetNext OIDs", proto: "snmp", kind: "get_next_request", key: "oids", value: "1.3.6.1.2.1.1.5.0", count: 1, contains: true},
		},
	},
	{
		protocol: "rdp",
		port:     3389,
		decoder:  func() dpi.Decoder { return itdpi.NewRDPDecoder() },
		wants: []itExpectation{
			{label: "RDP X.224 connection request", proto: "rdp", kind: "connection_request", count: 1},
			{label: "RDP TLS negotiation", proto: "rdp", kind: "negotiation", key: "selected_protocol", value: "tls", count: 1},
		},
	},
	{
		// smb.pcap is the Apache-2.0 capture of unmodified Debian Samba and
		// smbclient 4.17.12 negotiation; its capture harness and notices are
		// documented in test/it/testdata/README.md.
		protocol: "smb",
		port:     445,
		decoder:  func() dpi.Decoder { return itdpi.NewSMBDecoder() },
		wants: []itExpectation{
			{label: "SMB negotiate", proto: "smb", kind: "negotiate", key: "version", value: "SMB2", count: 1},
			{label: "SMB offered dialects", proto: "smb", kind: "negotiate", key: "dialects_offered", value: "3.1.1", count: 1, contains: true},
			{label: "SMB selected dialect", proto: "smb", kind: "negotiate", key: "dialect", value: "3.1.1", count: 1},
			{label: "SMB session setup", proto: "smb", kind: "session_setup", count: 1},
			{label: "SMB tree connect", proto: "smb", kind: "tree_connect", count: 1},
			{label: "SMB file read", proto: "smb", kind: "read", count: 1},
		},
	},
}

// TestITRecordedCaptureDecoders keeps independently generated IT traffic on the
// real Manager replay path and reports decoder coverage gaps without editing
// decoder implementations to make a capture pass.
func TestITRecordedCaptureDecoders(t *testing.T) {
	directory := os.Getenv("CONTAIND_IT_CAPTURE_DIR")
	if directory == "" {
		directory = filepath.Join("../../../..", "test", "it", "testdata")
	}
	data, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest itCaptureManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if manifest.Version != 1 {
		t.Fatalf("unsupported capture manifest version %d", manifest.Version)
	}
	entries := make(map[string]itCaptureEntry, len(manifest.Captures))
	for _, entry := range manifest.Captures {
		if entry.Protocol == "" || entry.PCAP != entry.Protocol+".pcap" || entry.Frames < 1 || entry.Shows == "" {
			t.Fatalf("invalid capture manifest entry: %+v", entry)
		}
		if _, duplicate := entries[entry.Protocol]; duplicate {
			t.Fatalf("duplicate %s manifest entry", entry.Protocol)
		}
		entries[entry.Protocol] = entry
	}
	if len(entries) != len(itDecoderCases) {
		t.Fatalf("manifest has %d captures, want %d", len(entries), len(itDecoderCases))
	}

	for _, decoderCase := range itDecoderCases {
		decoderCase := decoderCase
		t.Run(decoderCase.protocol, func(t *testing.T) {
			entry, ok := entries[decoderCase.protocol]
			if !ok {
				t.Fatalf("manifest missing %s capture", decoderCase.protocol)
			}
			file, err := os.Open(filepath.Join(directory, entry.PCAP))
			if err != nil {
				t.Fatal(err)
			}
			packets, skipped, readErr := corpus.ReadPCAP(file, entry.PCAP, corpus.ReadOptions{})
			closeErr := file.Close()
			if readErr != nil {
				t.Fatalf("read %s: %v", entry.PCAP, readErr)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			if len(skipped) != 0 {
				t.Fatalf("%s contains unaccounted skipped records: %+v", entry.PCAP, skipped)
			}
			if len(packets) != entry.Frames {
				t.Fatalf("%s frame count=%d, manifest=%d", entry.PCAP, len(packets), entry.Frames)
			}

			fixture, clientFrames := makeITFixture(decoderCase.protocol, decoderCase.port, packets)
			steps, err := corpus.Replay(
				func() *dpi.Manager { return dpi.NewManager(decoderCase.decoder()) },
				fixture,
				corpus.ReplayOptions{SimulateHandshake: true},
			)
			if err != nil {
				t.Fatal(err)
			}

			var observed []itObservedEvent
			var eventFrames []int
			for _, step := range steps {
				frame := 0
				if len(step.Packet.Source) > 0 {
					frame = step.Packet.Source[0].Frame
				}
				if step.Result.Err != nil {
					t.Logf("FINDING %s frame %d: replay result error: %v", entry.PCAP, frame, step.Result.Err)
				}
				if step.Kind != "inspect" {
					continue
				}
				for _, event := range step.Result.Events {
					observed = append(observed, itObservedEvent{frame: frame, event: event})
					eventFrames = append(eventFrames, frame)
				}
			}

			for _, want := range decoderCase.wants {
				matched := 0
				var candidateFrames []int
				for _, got := range observed {
					if got.event.Proto != want.proto || got.event.Kind != want.kind {
						continue
					}
					candidateFrames = append(candidateFrames, got.frame)
					if want.key == "" || matchesITExpectation(got.event.Attributes[want.key], want) {
						matched++
					}
				}
				if matched >= want.count {
					continue
				}
				frames := candidateFrames
				if len(frames) == 0 {
					frames = clientFrames
				}
				if len(candidateFrames) == 0 {
					t.Errorf(
						"FINDING %s frame(s) %v: decoder produced no %s/%s events for %s",
						entry.PCAP, frames, want.proto, want.kind, want.label,
					)
				} else if want.gap {
					t.Logf(
						"FINDING %s frame(s) %v: %s missing (matched %d, want %d)",
						entry.PCAP, frames, want.label, matched, want.count,
					)
				} else {
					t.Errorf(
						"%s frame(s) %v: %s missing (matched %d, want %d)",
						entry.PCAP, frames, want.label, matched, want.count,
					)
				}
			}

			sort.Ints(eventFrames)
			t.Logf(
				"%s: frames=%d payload-client-frames=%v events=%d event-frames=%v shows=%q",
				entry.PCAP, len(packets), clientFrames, len(observed), eventFrames, entry.Shows,
			)
			for _, got := range observed {
				t.Logf(
					"  frame=%d event=%s/%s attrs={%s}",
					got.frame, got.event.Proto, got.event.Kind, stableITAttributes(got.event),
				)
			}
		})
	}
}

func stableITAttributes(event dpi.Event) string {
	keysByProtocol := map[string][]string{
		"dns":  {"qname", "qtype", "rcode"},
		"tls":  {"sni", "alpn", "tls_version"},
		"http": {"method", "path", "host", "user_agent", "status"},
		"ssh":  {"version", "software", "kex_algorithm", "encryption"},
		"ntp":  {"mode_name", "stratum"},
		"snmp": {"version", "community", "pdu_type", "oids", "trap_oid", "msg_flags_auth", "msg_flags_priv", "msg_security_model", "user_name"},
		"rdp":  {"stage", "cookie", "requested_protocols", "selected_protocol"},
		"smb":  {"version", "command", "dialects_offered", "dialect", "share"},
	}
	var fields []string
	for _, key := range keysByProtocol[event.Proto] {
		if value, ok := event.Attributes[key]; ok {
			fields = append(fields, fmt.Sprintf("%s=%v", key, value))
		}
	}
	return strings.Join(fields, " ")
}

func matchesITExpectation(value any, want itExpectation) bool {
	if want.contains {
		switch values := value.(type) {
		case []string:
			for _, candidate := range values {
				if candidate == want.value {
					return true
				}
			}
			return false
		case string:
			return strings.Contains(values, want.value)
		default:
			return false
		}
	}
	return fmt.Sprint(value) == want.value
}

func makeITFixture(protocol string, serverPort uint16, packets []corpus.Packet) (corpus.Fixture, []int) {
	fixture := corpus.Fixture{Name: protocol}
	var clientFrames []int
	for _, packet := range packets {
		decoded := packet.Decoded
		src := net.JoinHostPort(net.IP(decoded.SrcIP).String(), strconv.Itoa(int(decoded.SrcPort)))
		dst := net.JoinHostPort(net.IP(decoded.DstIP).String(), strconv.Itoa(int(decoded.DstPort)))
		var direction dpi.StreamDir
		switch {
		case decoded.DstPort == serverPort:
			direction = dpi.ClientToServer
			if len(decoded.Payload) > 0 {
				clientFrames = append(clientFrames, packet.Source[0].Frame)
			}
		case decoded.SrcPort == serverPort:
			direction = dpi.ServerToClient
		default:
			panic(fmt.Sprintf("%s frame %d has no service endpoint on port %d", protocol, packet.Source[0].Frame, serverPort))
		}
		left, right := src, dst
		if right < left {
			left, right = right, left
		}
		packet.Connection = protocol + "/" + left + "/" + right
		packet.Dir = direction
		fixture.Packets = append(fixture.Packets, packet)
	}
	return fixture, clientFrames
}
