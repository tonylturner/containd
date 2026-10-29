// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"encoding/binary"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/ics"
)

func join(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

func transaction(b []byte, tid uint16) []byte {
	b = join(b)
	binary.BigEndian.PutUint16(b, tid)
	return b
}

func TestWalkModbusPairs(t *testing.T) {
	f := fixtures()[0]
	a := join(transaction(f.request, 1), transaction(f.request, 2))
	b := join(transaction(f.reply, 2), transaction(f.reply, 1))
	for _, reverse := range [][]byte{b, b[:len(f.reply)]} {
		if r := Probe(Modbus, ics.TCP, a, reverse); r.State != Confirmed {
			t.Fatal("reordered/coalesced transactions", r)
		}
	}
	// A complete later transaction must not be hidden by an unrelated first one.
	if r := Probe(Modbus, ics.TCP, a, transaction(f.reply, 2)); r.State != Confirmed {
		t.Fatal(r)
	}
}

func TestWalkIECAdjacentPairs(t *testing.T) {
	s := []byte{0x68, 4, 1, 0, 0, 0}
	i := []byte{0x68, 14, 0, 0, 0, 0, 1, 1, 3, 0, 1, 0, 1, 0, 0, 1}
	for _, tail := range [][]byte{fixtures()[2].request, i} {
		if r := Probe(IEC104, ics.TCP, join(s, s, tail), nil); r.State != Confirmed {
			t.Fatal("later adjacent pair", r)
		}
	}
	if r := Probe(IEC104, ics.TCP, join(s, s, fixtures()[2].request), fixtures()[2].reply); r.State != Confirmed {
		t.Fatal("later U handshake", r)
	}
}

func TestWalkTrailingGarbage(t *testing.T) {
	for _, f := range fixtures() {
		if f.protocol == DNP3 {
			continue // the DNP3 link CRC is independent first-frame evidence
		}
		if r := Probe(f.protocol, ics.TCP, join(f.request, []byte("GARBAGE!")), nil); r.State != Reject {
			t.Fatal(f.protocol, r)
		}
	}
}

func TestWalkNOPAndRegister(t *testing.T) {
	f := fixtures()[3]
	for _, nop := range [][]byte{make([]byte, 24), encapsulate(0, 0, []byte{1, 2, 3})} {
		if r := Probe(ENIP, ics.TCP, nop, nil); r.State != NeedMore {
			t.Fatal("NOP is neutral", r)
		}
		if r := Probe(ENIP, ics.TCP, join(nop, f.request), join(nop, f.reply)); r.State != Confirmed {
			t.Fatal("NOP hides later frame", r)
		}
		if r := Probe(ENIP, ics.UDP, nop, nil); r.State != NeedMore {
			t.Fatal("UDP NOP is neutral", r)
		}
	}
}

func extraCPF(b []byte, count int) []byte {
	b = join(b)
	for n := 0; n < count; n++ {
		b = append(b, byte(0x00+n), 0x80, 16, 0)
		b = append(b, make([]byte, 16)...)
	}
	binary.LittleEndian.PutUint16(b[30:], uint16(2+count))
	binary.LittleEndian.PutUint16(b[2:], uint16(len(b)-24))
	return b
}

func TestWalkCPFExtraItems(t *testing.T) {
	for _, cmd := range []uint16{0x6f, 0x70} {
		for _, extra := range []int{1, 2} {
			a, b := extraCPF(explicit(cmd, false), extra), extraCPF(explicit(cmd, true), extra)
			if r := Probe(ENIP, ics.TCP, a, b); r.State != Confirmed {
				t.Fatal("valid CPF extensions", cmd, extra, r)
			}
			b[len(b)-20] = 0xff
			if r := Probe(ENIP, ics.TCP, a, b); r.State != Candidate {
				t.Fatal("unknown extension was accepted", r)
			}
		}
	}
}

func TestWalkUDPCommands(t *testing.T) {
	for _, b := range [][]byte{fixtures()[3].request, explicit(0x6f, false), explicit(0x70, false)} {
		if r := Probe(ENIP, ics.UDP, b, nil); r.State != Reject {
			t.Fatal("TCP-only command over UDP", r)
		}
	}
}

func TestWalkEmptyLists(t *testing.T) {
	for _, cmd := range []uint16{0x63, 0x64} {
		for _, transport := range []uint8{ics.TCP, ics.UDP} {
			if r := Probe(ENIP, transport, encapsulate(cmd, 0, []byte{0, 0}), nil); r.State != Candidate {
				t.Fatal(cmd, transport, r)
			}
		}
	}
}

func TestWalkErrorReplies(t *testing.T) {
	for _, status := range []uint32{1, 2, 3, 0x64, 0x65, 0x69} {
		for _, cmd := range []uint16{0x65, 0x6f, 0x70, 4} {
			a, b := fixtures()[3].request, encapsulate(0x65, 0, []byte{1, 0, 0, 0})
			if cmd == 4 {
				a, b = encapsulate(cmd, 0, nil), encapsulate(cmd, 0, nil)
			} else if cmd != 0x65 {
				a, b = explicit(cmd, false), encapsulate(cmd, 42, nil)
			}
			binary.LittleEndian.PutUint32(b[8:], status)
			if r := Probe(ENIP, ics.TCP, b, nil); r.State != Candidate {
				t.Fatal("error reply alone", cmd, status, r)
			}
			if r := Probe(ENIP, ics.TCP, a, b); r.State != Confirmed {
				t.Fatal("paired error reply", cmd, status, r)
			}
			b[12]++
			if r := Probe(ENIP, ics.TCP, a, b); r.State != Candidate {
				t.Fatal("mismatched error context", r)
			}
		}
	}
}

func TestWalkDirectionContradiction(t *testing.T) {
	if r := Probe(DNP3, ics.TCP, []byte("GET / HTTP/1.1\r\n\r\n"), link(nil)); r.State != Candidate || r.States != [2]State{Reject, Confirmed} {
		t.Fatal("opposite reject hidden", r)
	}
}

func TestWalkFCBIgnored(t *testing.T) {
	for _, control := range []byte{0xe4, 0xe9} {
		b := link(nil)
		b[3] = control
		copy(b[8:], testCRC(b[:8]))
		if r := Probe(DNP3, ics.TCP, b, nil); r.State != Confirmed {
			t.Fatal(control, r)
		}
	}
}
