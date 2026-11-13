// SPDX-License-Identifier: Apache-2.0

package itdpi

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func helloWithExtensions(ext []byte) []byte {
	b := buildClientHello("", nil)[9:]
	b = append([]byte(nil), b[:len(b)-2]...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(ext)))
	b = append(b, ext...)
	return tlsRecord(append([]byte{1, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}, b...))
}

func TestTLSRepeatedPointFormats(t *testing.T) {
	// salesforce/ja3 python/ja3.py at 502cc6395811c54743b0561419d61900a6df3ff7
	// process_extensions assigns (rather than appends) each point-format list.
	raw := helloWithExtensions([]byte{0, 11, 0, 2, 1, 0, 0, 10, 0, 4, 0, 2, 0, 23, 0, 11, 0, 3, 2, 1, 2})
	m := parseClientHello(raw[9:])
	if m.JA3 != "771,4865-49199,11-10-11,23,1-2" {
		t.Fatal(m.JA3)
	}
}

func TestTLSCompatibilityCCS(t *testing.T) {
	for _, offer13 := range []bool{false, true} {
		var ext []byte
		if offer13 {
			ext = []byte{0, 43, 0, 5, 4, 3, 4, 3, 3}
		}
		hello := helloWithExtensions(ext)
		raw := append(append([]byte(nil), hello...), 20, 3, 3, 0, 1, 1)
		raw = append(raw, hello...)
		mgr := dpi.NewManager(NewTLSDecoder())
		st := tlsFlowState(12345, 443)
		count := 0
		for i, b := range raw {
			r := mgr.Inspect(st, &dpi.ParsedPacket{Proto: "tcp", Payload: []byte{b}, TCPSeqValid: true, TCPSeq: uint32(100 + i)})
			if r.Err != nil {
				t.Fatal(r.Err)
			}
			for _, e := range r.Events {
				if e.Kind != "client_hello" {
					t.Fatal(e)
				}
				count++
			}
		}
		want := 1
		if offer13 {
			want = 2
		}
		if count != want {
			t.Fatalf("offer13=%v got %d hellos", offer13, count)
		}
	}
}

func TestTLSCCSUsesServerSelection(t *testing.T) {
	for _, selected13 := range []bool{false, true} {
		d := NewTLSDecoder()
		mgr := dpi.NewManager(d)
		client := tlsFlowState(12345, 443)
		server := tlsFlowState(443, 12345)
		server.Key.SrcIP, server.Key.DstIP = client.Key.DstIP, client.Key.SrcIP
		ch := helloWithExtensions([]byte{0, 43, 0, 5, 4, 3, 4, 3, 3})
		sh := append([]byte{3, 3}, make([]byte, 32)...)
		sh = append(sh, 0, 0x13, 1, 0)
		if selected13 {
			// RFC 8446 4.1.3 HelloRetryRequest random and selected TLS 1.3.
			random, err := hex.DecodeString("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
			if err != nil {
				t.Fatal(err)
			}
			copy(sh[2:34], random)
			sh = append(sh, 0, 6, 0, 43, 0, 2, 3, 4)
		}
		for i, p := range []struct {
			reply bool
			seq   uint32
			data  []byte
		}{
			{false, 100, ch},
			{true, 200, tlsRecord(append([]byte{2, 0, 0, byte(len(sh))}, sh...))},
			{false, uint32(100 + len(ch)), append([]byte{20, 3, 3, 0, 1, 1}, ch...)},
		} {
			st := client
			if p.reply {
				st = server
			}
			r := mgr.Inspect(st, &dpi.ParsedPacket{Proto: "tcp", Payload: p.data, TCPSeqValid: true, TCPSeq: p.seq})
			if r.Err != nil {
				t.Fatal(r.Err)
			}
			want := 1
			if i == 2 && !selected13 {
				want = 0
			}
			if len(r.Events) != want {
				t.Fatalf("selected13=%v step=%d: %v", selected13, i, r.Events)
			}
		}
	}
}

func TestTLSRecordProgressAndLargeCertificate(t *testing.T) {
	d := NewTLSDecoder()
	st := tlsFlowState(443, 12345)
	header := []byte{11, 1, 0, 0} // 64 KiB Certificate, not a hello-size violation
	if r, err := d.ParseStream(st, dpi.StreamView{Session: "progress", Bytes: tlsRecord(header)}); err != nil || r.Consumed != 9 {
		t.Fatalf("header: %+v %v", r, err)
	}
	for i := 0; i < 65536; i++ {
		r, err := d.ParseStream(st, dpi.StreamView{Session: "progress", Base: int64(9 + 6*i), Bytes: tlsRecord([]byte{0})})
		if err != nil || r.Consumed != 6 || len(r.Frames) != 1 || len(r.Frames[0].Events) != 0 {
			t.Fatalf("record %d: %+v %v", i, r, err)
		}
	}
	s := d.streams[tlsStreamKey{"progress", dpi.DirUnknown}]
	if s.hello != nil || s.remaining != 0 || s.headerN != 0 {
		t.Fatalf("retained certificate: %+v", s)
	}
	d.StreamEnded("progress", dpi.DirUnknown)
	if len(d.streams) != 0 || len(d.connections) != 0 {
		t.Fatal("stream state leaked")
	}
}

func TestTLSHelloBufferGrowsWithReceivedBytes(t *testing.T) {
	d := NewTLSDecoder()
	st := tlsFlowState(12345, 443)
	headerOnly := []byte{22, 3, 3, 0, 4, 1, 1, 0, 0}
	r, err := d.ParseStream(st, dpi.StreamView{Session: "header-only", Bytes: headerOnly})
	if err != nil || r.Consumed != len(headerOnly) {
		t.Fatalf("header-only record: %+v %v", r, err)
	}
	stream := d.streams[tlsStreamKey{session: "header-only"}]
	if stream == nil {
		t.Fatal("TLS stream not retained")
	}
	if cap(stream.hello) > len(headerOnly)+16 {
		t.Fatalf("hello capacity %d exceeds bytes received %d plus small overhead", cap(stream.hello), len(headerOnly))
	}

	// Accumulating a handshake a byte at a time across many TLS records still
	// produces the same ClientHello event.
	hello := buildClientHello("example.com", nil)
	handshake := hello[5:]
	var records []byte
	for _, b := range handshake {
		records = append(records, tlsRecord([]byte{b})...)
	}
	d = NewTLSDecoder()
	r, err = d.ParseStream(tlsFlowState(12345, 443), dpi.StreamView{Session: "many-records", Bytes: records})
	if err != nil || r.Consumed != len(records) || len(r.Frames) != len(handshake) {
		t.Fatalf("many-record ClientHello: frames=%d consumed=%d/%d err=%v", len(r.Frames), r.Consumed, len(records), err)
	}
	last := r.Frames[len(r.Frames)-1]
	if len(last.Events) != 1 || last.Events[0].Kind != "client_hello" || last.Events[0].Attributes["sni"] != "example.com" {
		t.Fatalf("many-record ClientHello event: %+v", last.Events)
	}
}

func BenchmarkTLSRecordProgress(b *testing.B) {
	for _, size := range []int{0, 60000} {
		b.Run(stringName(size), func(b *testing.B) {
			mgr := dpi.NewManager(NewTLSDecoder())
			st := tlsFlowState(12345, 443)
			seq := uint32(100)
			send := func(p []byte) {
				r := mgr.Inspect(st, &dpi.ParsedPacket{Proto: "tcp", Payload: p, TCPSeqValid: true, TCPSeq: seq})
				seq += uint32(len(p))
				if r.Err != nil || len(r.Events) != 0 {
					b.Fatal(r.Err, r.Events)
				}
			}
			pre := tlsRecord([]byte{11, 0xff, 0xff, 0xff})
			pre = append(pre, bytes.Repeat(tlsRecord([]byte{0}), size/6)...)
			send(pre)
			record := tlsRecord([]byte{0})
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				send(record[i%6 : i%6+1])
			}
		})
	}
}
func stringName(n int) string {
	if n == 0 {
		return "fresh"
	}
	return "after_60KB"
}
