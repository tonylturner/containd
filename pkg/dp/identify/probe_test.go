// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/ics"
)

type fixture struct {
	protocol Protocol
	port     uint16
	header   int
	request  []byte
	reply    []byte
}

func fixtures() []fixture {
	return []fixture{
		{Modbus, 502, 8, []byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1}, []byte{0, 1, 0, 0, 0, 5, 1, 3, 2, 0, 1}},
		{DNP3, 20000, 10, link(nil), nil},
		{IEC104, 2404, 6, []byte{0x68, 4, 7, 0, 0, 0}, []byte{0x68, 4, 11, 0, 0, 0}},
		{ENIP, 44818, 24, encapsulate(0x65, 0, []byte{1, 0, 0, 0}), encapsulate(0x65, 42, []byte{1, 0, 0, 0})},
	}
}

func encapsulate(command uint16, session uint32, body []byte) []byte {
	b := make([]byte, 24+len(body))
	binary.LittleEndian.PutUint16(b, command)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(body)))
	binary.LittleEndian.PutUint32(b[4:], session)
	b[12] = 17
	copy(b[24:], body)
	return b
}

// Independent bitwise CRC fixture builder; production uses the DNP3 reader.
func link(data []byte) []byte {
	crc := func(b []byte) []byte {
		var c uint16
		for _, v := range b {
			c ^= uint16(v)
			for range 8 {
				if c&1 != 0 {
					c = c>>1 ^ 0xa6bc
				} else {
					c >>= 1
				}
			}
		}
		return []byte{byte(^c), byte(^c >> 8)}
	}
	b := []byte{5, 0x64, byte(5 + len(data)), 0xc4, 1, 0, 2, 0}
	b = append(b, crc(b)...)
	for len(data) > 0 {
		n := min(16, len(data))
		b = append(b, data[:n]...)
		b = append(b, crc(data[:n])...)
		data = data[n:]
	}
	return b
}

func TestProbeFixtures(t *testing.T) {
	for _, f := range fixtures() {
		t.Run(string(f.protocol), func(t *testing.T) {
			want := Candidate
			if f.protocol == DNP3 {
				want = Confirmed
			}
			r := Probe(f.protocol, ics.TCP, f.request, nil)
			if r.State != want || r.Version != ProfileVersion || r.Examined[0].End != len(f.request) {
				t.Fatalf("%+v", r)
			}
			r = Probe(f.protocol, ics.TCP, f.request, f.reply)
			if r.State != Confirmed {
				t.Fatalf("%+v", r)
			}
			r = Probe(f.protocol, ics.TCP, f.reply, f.request)
			if r.State != Confirmed {
				t.Fatalf("reverse: %+v", r)
			}
		})
	}
}

func TestProtocolTraps(t *testing.T) {
	weakI := []byte{0x68, 14, 0, 0, 0, 0, 1, 1, 3, 0, 1, 0, 1, 0, 0, 1}
	for _, tc := range []struct {
		name string
		p    Protocol
		b    []byte
		want State
	}{
		{"zero NOP", ENIP, make([]byte, 24), Reject},
		{"nonempty NOP", ENIP, encapsulate(0, 0, []byte{1, 2}), Reject},
		{"I prefix", IEC104, weakI[:6], NeedMore},
		{"single I", IEC104, weakI, Candidate},
		{"two I", IEC104, append(append([]byte(nil), weakI...), weakI...), Confirmed},
		{"two S", IEC104, []byte{0x68, 4, 1, 0, 0, 0, 0x68, 4, 1, 0, 0, 0}, Candidate},
		{"bad U", IEC104, []byte{0x68, 4, 3, 0, 0, 0}, Reject},
		{"bad S length", IEC104, []byte{0x68, 5, 1, 0, 0, 0, 0}, Reject},
		{"unknown ASDU", IEC104, []byte{0x68, 10, 0, 0, 0, 0, 200, 1, 3, 0, 1, 0}, Candidate},
		{"nonzero PID", Modbus, []byte{0, 1, 0, 1, 0, 6, 1, 3, 0, 0, 0, 1}, Reject},
		{"bad byte count", Modbus, []byte{0, 1, 0, 0, 0, 5, 1, 3, 4, 0, 1}, Reject},
		{"private FC", Modbus, []byte{0, 1, 0, 0, 0, 2, 1, 100}, Candidate},
		{"bad header CRC", DNP3, []byte{5, 0x64, 5, 0xc4, 1, 0, 2, 0, 0, 0}, Reject},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Probe(tc.p, ics.TCP, tc.b, nil)
			if r.State != tc.want {
				t.Fatalf("want %s got %+v", tc.want, r)
			}
		})
	}
	b := link(make([]byte, 40))
	if r := Probe(DNP3, ics.TCP, b, nil); r.State != Confirmed {
		t.Fatal(r)
	}
	b[len(b)-1] ^= 1
	if r := Probe(DNP3, ics.TCP, b, nil); r.State != Reject {
		t.Fatal(r)
	}
	for _, f := range fixtures() {
		if len(f.reply) == 0 {
			continue
		}
		bad := append([]byte(nil), f.reply...)
		switch f.protocol {
		case Modbus:
			bad[1]++
		case IEC104:
			bad[2] = 0x23
		case ENIP:
			bad[12]++
		}
		if r := Probe(f.protocol, ics.TCP, f.request, bad); r.State == Confirmed {
			t.Fatalf("mismatched pair: %+v", r)
		}
	}
}

func explicit(command uint16, response bool) []byte {
	body := []byte{0, 0, 0, 0, 0, 0, 2, 0}
	if command == 0x70 {
		body = append(body, 0xa1, 0, 4, 0, 1, 0, 0, 0)
	} else {
		body = append(body, 0, 0, 0, 0)
	}
	message := []byte{0x0e, 2, 0x20, 1, 0x24, 1}
	if response {
		message = []byte{0x8e, 0, 0, 0}
	}
	id := byte(0xb2)
	if command == 0x70 {
		id = 0xb1
		message = append([]byte{1, 0}, message...)
	}
	body = append(body, id, 0, byte(len(message)), 0)
	return encapsulate(command, 42, append(body, message...))
}

func TestENIPProfiles(t *testing.T) {
	for _, transport := range []uint8{ics.TCP, ics.UDP} {
		for _, cmd := range []uint16{0x6f, 0x70} {
			a, b := explicit(cmd, false), explicit(cmd, true)
			if r := Probe(ENIP, transport, a, nil); r.State != Candidate {
				t.Fatal(r)
			}
			if r := Probe(ENIP, transport, a, b); r.State != Confirmed {
				t.Fatal(r)
			}
			b[24] = 1 // nonzero interface handle
			if r := Probe(ENIP, transport, a, b); r.State == Confirmed {
				t.Fatal(r)
			}
		}
		for _, cmd := range []uint16{4, 0x63, 0x64} {
			var body []byte
			switch cmd {
			case 4:
				body = append([]byte{1, 0, 0, 1, 20, 0, 1, 0}, make([]byte, 18)...)
			case 0x63:
				body = append([]byte{1, 0, 0xc, 0, 34, 0, 1, 0}, make([]byte, 32)...)
			case 0x64:
				body = []byte{0, 0}
			}
			raw := encapsulate(cmd, 0, body)
			if r := Probe(ENIP, transport, raw, nil); r.State != Confirmed {
				t.Fatalf("cmd=%x: %+v", cmd, r)
			}
			raw = append(raw, 1)
			binary.LittleEndian.PutUint16(raw[2:], uint16(len(raw)-24))
			if r := Probe(ENIP, transport, raw, nil); r.State == Confirmed {
				t.Fatal(r)
			}
		}
	}
	for _, b := range [][]byte{{0x65}, fixtures()[3].request[:24], append(fixtures()[3].request, 0)} {
		if r := Probe(ENIP, ics.UDP, b, nil); r.State != Reject {
			t.Fatal(r)
		}
	}
	oversized := append(explicit(0x6f, true), make([]byte, 65514)...)
	binary.LittleEndian.PutUint16(oversized[2:], uint16(len(oversized)-24))
	binary.LittleEndian.PutUint16(oversized[38:], uint16(len(oversized)-40))
	if r := Probe(ENIP, ics.TCP, explicit(0x6f, false), oversized); r.State != Candidate {
		t.Fatal("pairing bypassed the partner's frame-size limit", r)
	}
}

func negativeCorpus() [][]byte {
	random := make([]byte, 1024)
	_, _ = rand.New(rand.NewSource(104)).Read(random)
	// Synthetic TLS handshake record with a ClientHello header and TLS 1.2
	// legacy version. No network or optional capture tools are needed.
	tls := append([]byte{0x16, 3, 1, 0, 47, 1, 0, 0, 43, 3, 3}, make([]byte, 32)...)
	tls = append(tls, 0, 0, 2, 0x13, 1, 1, 0, 0, 0)
	return [][]byte{tls, []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
		[]byte("SSH-2.0-OpenSSH_9.9\r\n"), random, make([]byte, 1024)}
}

func TestNegativeCorpus(t *testing.T) {
	for i, b := range negativeCorpus() {
		for _, p := range protocols {
			for n := 1; n <= len(b); n++ {
				if r := Probe(p, ics.TCP, b[:n], nil); r.State == Confirmed {
					t.Fatalf("corpus %d prefix %d: %+v", i, n, r)
				}
			}
		}
	}
}

func FuzzProbe(f *testing.F) {
	for _, s := range fixtures() {
		f.Add(s.request, s.reply)
	}
	for _, b := range negativeCorpus() {
		f.Add(b, []byte(nil))
	}
	f.Fuzz(func(t *testing.T, a, b []byte) {
		a, b = a[:min(len(a), 1024)], b[:min(len(b), 1024)]
		for _, p := range protocols {
			for _, transport := range []uint8{ics.TCP, ics.UDP} {
				r := Probe(p, transport, a, b)
				if r.Examined[0].End > len(a) || r.Examined[1].End > len(b) {
					t.Fatal(r)
				}
			}
		}
	})
}

var benchmarkResult Result

func BenchmarkProbe(b *testing.B) {
	for _, f := range fixtures() {
		b.Run(string(f.protocol), func(b *testing.B) {
			for _, tc := range []struct {
				name string
				a, c []byte
			}{
				{"reject", []byte("GET / HTTP/1.1\r\n\r\n"), nil},
				{"candidate", f.request, nil},
				{"confirm", f.request, f.reply},
			} {
				b.Run(tc.name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						benchmarkResult = Probe(f.protocol, ics.TCP, tc.a, tc.c)
					}
				})
			}
		})
	}
}
