// SPDX-License-Identifier: Apache-2.0

package itdpi

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

// These synthetic wire fixtures were fingerprinted independently with
// salesforce/ja3 python/ja3.py process_pcap at commit
// 502cc6395811c54743b0561419d61900a6df3ff7, using dpkt 1.9.8.
// https://github.com/salesforce/ja3/blob/502cc6395811c54743b0561419d61900a6df3ff7/python/ja3.py
// Expected strings and digests are saved, never calculated by the decoder.
func TestTLSJA3Reference(t *testing.T) {
	b, err := os.ReadFile("../../../test/it/testdata/ja3-reference.json")
	if err != nil {
		t.Fatal(err)
	}
	var ref struct {
		Fixtures []struct {
			Name string
			Hex  string `json:"client_hello_hex"`
			JA3  string
			MD5  string
		}
	}
	if err := json.Unmarshal(b, &ref); err != nil {
		t.Fatal(err)
	}
	if len(ref.Fixtures) != 3 {
		t.Fatal("reference fixtures missing")
	}
	for _, f := range ref.Fixtures {
		t.Run(f.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(f.Hex)
			if err != nil {
				t.Fatal(err)
			}
			for split := 0; split <= len(raw); split++ {
				st := tlsFlowState(12345, 443)
				mgr := dpi.NewManager(NewTLSDecoder())
				var events []dpi.Event
				for i, p := range [][]byte{raw[:split], raw[split:]} {
					off := int64(0)
					if i == 1 {
						off = int64(split)
					}
					r := mgr.Inspect(st, &dpi.ParsedPacket{Payload: p, Proto: "tcp", SrcPort: 12345, DstPort: 443, HasOffset: true, Session: "tls", Dir: dpi.ClientToServer, Offset: off})
					if r.Err != nil {
						t.Fatalf("split %d: %v", split, r.Err)
					}
					events = append(events, r.Events...)
				}
				if len(events) != 1 {
					t.Fatalf("split %d: events=%v", split, events)
				}
				a := events[0].Attributes
				if a["ja3"] != f.JA3 || a["ja3_hash"] != f.MD5 {
					t.Fatalf("split %d: JA3=%v hash=%v", split, a["ja3"], a["ja3_hash"])
				}
				if a["tls_legacy_version"] != "TLS1.2" || !reflect.DeepEqual(a["tls_offered_versions"], []string{"TLS1.3", "TLS1.2"}) {
					t.Fatalf("versions: %v", a)
				}
			}
			// Handshakes may cross TLS record boundaries as well as TCP segments.
			hs := raw[5:]
			split := len(hs) / 2
			records := tlsRecord(hs[:split])
			records = append(records, tlsRecord(hs[split:])...)
			r, err := NewTLSDecoder().ParseStream(tlsFlowState(12345, 443), dpi.StreamView{Bytes: records})
			if err != nil || r.Consumed != len(records) || len(r.Frames) != 2 || len(r.Frames[0].Events) != 0 || len(r.Frames[1].Events) != 1 || r.Frames[1].Events[0].Attributes["ja3_hash"] != f.MD5 {
				t.Fatalf("cross-record: %+v %v", r, err)
			}
		})
	}
}

func tlsRecord(hs []byte) []byte {
	b := []byte{22, 3, 3}
	b = binary.BigEndian.AppendUint16(b, uint16(len(hs)))
	return append(b, hs...)
}

func TestTLSSelectedVersion(t *testing.T) {
	for _, version := range []uint16{0x0303, 0x0304} {
		body := append([]byte{3, 3}, make([]byte, 32)...)
		body = append(body, 0, 0x13, 1, 0)
		if version == 0x0304 {
			body = append(body, 0, 6, 0, 43, 0, 2, 3, 4)
		}
		raw := tlsRecord(append([]byte{2, 0, 0, byte(len(body))}, body...))
		for split := 0; split <= len(raw); split++ {
			mgr := dpi.NewManager(NewTLSDecoder())
			st := tlsFlowState(443, 12345)
			var events []dpi.Event
			for i, p := range [][]byte{raw[:split], raw[split:]} {
				off := int64(0)
				if i == 1 {
					off = int64(split)
				}
				r := mgr.Inspect(st, &dpi.ParsedPacket{Payload: p, Proto: "tcp", HasOffset: true, Session: "reply", Dir: dpi.ServerToClient, Offset: off})
				if r.Err != nil {
					t.Fatal(r.Err)
				}
				events = append(events, r.Events...)
			}
			if len(events) != 1 || events[0].Kind != "server_hello" || events[0].Attributes["tls_selected_version"] != tlsVersionString(version) || events[0].Attributes["tls_legacy_version"] != "TLS1.2" {
				t.Fatalf("version %x split %d: %v", version, split, events)
			}
			if _, ok := events[0].Attributes["ja3s"]; ok {
				t.Fatal("unexpected JA3S")
			}
		}
	}
}

func TestTLSBounds(t *testing.T) {
	raw := buildClientHello("example.com", nil)
	for n := 0; n < len(raw); n++ {
		r, err := NewTLSDecoder().ParseStream(tlsFlowState(1, 443), dpi.StreamView{Bytes: raw[:n]})
		if err != nil || r.Consumed != 0 || len(r.Frames) != 0 {
			t.Fatalf("truncated %d: %+v %v", n, r, err)
		}
	}
	// Unknown oversized records are silent pickups. Once a valid record has
	// anchored TLS, oversized hellos produce one event, not a manager restart.
	for _, tc := range []struct {
		raw       []byte
		malformed int
	}{
		{[]byte{22, 3, 3, 0xff, 0xff}, 0},
		{tlsRecord([]byte{1, 1, 0, 1}), 1},
	} {
		r, err := NewTLSDecoder().ParseStream(tlsFlowState(1, 443), dpi.StreamView{Bytes: tc.raw})
		if err != nil || r.Consumed != len(tc.raw) || len(r.Frames) != 1 || len(r.Frames[0].Events) != tc.malformed {
			t.Fatalf("bounds: %+v %v", r, err)
		}
	}

	// Old TLS clients without extensions still have a reference JA3 string.
	b := buildClientHello("", nil)[9:]
	b = b[:len(b)-2]
	if m := parseClientHello(b); m.JA3 != "771,4865-49199,,," {
		t.Fatalf("no extensions: %+v", m)
	}
}
