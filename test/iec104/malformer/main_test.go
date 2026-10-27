// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestDataBeforeStart(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	wire := make(chan []byte, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		data, err := io.ReadAll(conn)
		wire <- data
		serverErr <- err
	}()
	r := run(options{addr: listener.Addr().String(), scenario: "data-before-start", ca: 1, hold: 20 * time.Millisecond})
	if r.fatal != nil {
		t.Fatal(r.fatal)
	}
	// Exactly one valid GI, with initial sequence numbers and no U-frame.
	want := []byte{0x68, 14, 0, 0, 0, 0, 100, 1, 6, 0, 1, 0, 0, 0, 0, 20}
	if got := <-wire; !bytes.Equal(got, want) || r.sent != len(want) {
		t.Fatalf("sent %d bytes, wire % x, want % x", r.sent, got, want)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestDoubleCommandLayout(t *testing.T) {
	// SELECT, DCS=2 (close), CA 1, IOA 2001.
	asdu := doubleCommand(1, 2001, 2, true)
	want := []byte{
		46,   // type ID C_DC_NA_1
		0x01, // VSQ: SQ=0, count 1
		6, 0, // COT 6 (activation), originator 0
		1, 0, // CA 1, little-endian
		0xd1, 0x07, 0x00, // IOA 2001 = 0x7d1, three octets little-endian
		0x82, // DCO: S/E=1 (0x80) | DCS 2
	}
	if len(asdu) != len(want) {
		t.Fatalf("length %d, want %d (% x)", len(asdu), len(want), asdu)
	}
	for i := range want {
		if asdu[i] != want[i] {
			t.Fatalf("octet %d = 0x%02x, want 0x%02x (% x)", i, asdu[i], want[i], asdu)
		}
	}
}

func TestDoubleCommandExecuteMasksToTwoBits(t *testing.T) {
	// EXECUTE, DCS=1 (open); S/E must be 0 and only the low two bits set.
	dco := doubleCommand(1, 2001, 1, false)[9]
	if dco != 0x01 {
		t.Fatalf("DCO = 0x%02x, want 0x01", dco)
	}
}

func TestIFrameHeader(t *testing.T) {
	asdu := interrogation(1)
	frame := iFrame(0, 0, asdu)
	if frame[0] != startByte {
		t.Fatalf("start octet 0x%02x, want 0x68", frame[0])
	}
	if int(frame[1]) != 4+len(asdu) {
		t.Fatalf("length octet %d, want %d", frame[1], 4+len(asdu))
	}
	if len(frame) != 2+4+len(asdu) {
		t.Fatalf("frame length %d, want %d", len(frame), 2+4+len(asdu))
	}
	// Control octets 2-5 are the I-frame sequence fields, all zero for N(S)=N(R)=0.
	for i := 2; i < 6; i++ {
		if frame[i] != 0 {
			t.Fatalf("control octet %d = 0x%02x, want 0", i, frame[i])
		}
	}
}

func TestIFrameSequenceEncoding(t *testing.T) {
	// N(S) and N(R) are 15-bit, left-shifted by one into two little-endian octets.
	frame := iFrame(1, 2, interrogation(1))
	if frame[2] != 0x02 || frame[3] != 0x00 {
		t.Fatalf("N(S)=1 encoded as % x, want 02 00", frame[2:4])
	}
	if frame[4] != 0x04 || frame[5] != 0x00 {
		t.Fatalf("N(R)=2 encoded as % x, want 04 00", frame[4:6])
	}
}

func TestChecksum16KnownVector(t *testing.T) {
	// A minimal IPv4 header (RFC 1071 worked example) checksums to 0xb861.
	hdr := []byte{
		0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
		0xc0, 0xa8, 0x00, 0xc7,
	}
	if got := checksum16(hdr); got != 0xb861 {
		t.Fatalf("checksum 0x%04x, want 0xb861", got)
	}
}

func TestChecksum16OddLength(t *testing.T) {
	// The trailing odd byte is padded high; verify by appending a zero byte.
	odd := []byte{0x01, 0x02, 0x03}
	padded := []byte{0x01, 0x02, 0x03, 0x00}
	if checksum16(odd) != checksum16(padded) {
		t.Fatalf("odd-length checksum differs from zero-padded even-length")
	}
}

func TestBuildIPv4TCPChecksumsVerify(t *testing.T) {
	src := [4]byte{10, 233, 0, 10}
	dst := [4]byte{10, 234, 0, 10}
	payload := []byte("abcd")
	pkt := buildIPv4TCP(src, dst, 40404, 2404, 0x11223344, 0x55667788, tcpPSH|tcpACK, 65535, payload)

	if len(pkt) != 20+20+len(payload) {
		t.Fatalf("packet length %d, want %d", len(pkt), 40+len(payload))
	}
	if pkt[0] != 0x45 || pkt[9] != 6 {
		t.Fatalf("not an IPv4 TCP header: ver/ihl 0x%02x proto %d", pkt[0], pkt[9])
	}
	if binary.BigEndian.Uint16(pkt[2:]) != uint16(len(pkt)) {
		t.Fatalf("total length %d, want %d", binary.BigEndian.Uint16(pkt[2:]), len(pkt))
	}
	// A whole header including its own correct checksum sums to zero.
	if checksum16(pkt[:20]) != 0 {
		t.Fatalf("IP checksum does not verify")
	}
	pseudo := make([]byte, 12+20+len(payload))
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(20+len(payload)))
	copy(pseudo[12:], pkt[20:])
	if checksum16(pseudo) != 0 {
		t.Fatalf("TCP checksum does not verify")
	}
	tcp := pkt[20:]
	if binary.BigEndian.Uint32(tcp[4:]) != 0x11223344 {
		t.Fatalf("seq not carried")
	}
	if binary.BigEndian.Uint32(tcp[8:]) != 0x55667788 {
		t.Fatalf("ack not carried")
	}
	if tcp[13] != tcpPSH|tcpACK {
		t.Fatalf("flags 0x%02x, want 0x%02x", tcp[13], tcpPSH|tcpACK)
	}
}

func TestSeqGreaterWraps(t *testing.T) {
	cases := []struct {
		a, b uint32
		want bool
	}{
		{2, 1, true},
		{1, 2, false},
		{0, 0xffffffff, true}, // wrap: 0 is just after 2^32-1
		{0xffffffff, 0, false},
	}
	for _, c := range cases {
		if got := seqGreater(c.a, c.b); got != c.want {
			t.Errorf("seqGreater(%d,%d)=%v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestIFramesRepeatAndReservedBit(t *testing.T) {
	asdu := interrogation(1)
	frameLen := 6 + len(asdu)
	plain := iFrames(2, asdu, false)
	if len(plain) != 2*frameLen {
		t.Fatalf("two frames: %d bytes, want %d", len(plain), 2*frameLen)
	}
	// N(S) counts up from 0 (octet 2 = N(S) << 1); N(R) stays 0; no reserved bit.
	if plain[2] != 0x00 || plain[frameLen+2] != 0x02 || plain[4] != 0 || plain[frameLen+4] != 0 {
		t.Fatalf("control octets % x / % x, want N(S) 0 then 1 with N(R) 0", plain[2:6], plain[frameLen+2:frameLen+6])
	}
	if len(iFrames(0, asdu, false)) != frameLen {
		t.Fatalf("repeat 0 must still send one frame")
	}
	reserved := iFrames(1, asdu, true)
	if reserved[4] != 0x01 || reserved[5] != 0x00 || reserved[1] != byte(4+len(asdu)) {
		t.Fatalf("reserved frame % x: want octet 3 bit 0 set, N(R) 0 and the length unchanged", reserved[:6])
	}
	if !bytes.Equal(reserved[6:], asdu) {
		t.Fatalf("reserved bit must not touch the ASDU")
	}
}

func TestSinglePointLayout(t *testing.T) {
	// M_SP_NA_1 at CA 1 / IOA 1002 (0x3ea), spontaneous, SIQ off/good.
	want := []byte{1, 0x01, 3, 0, 1, 0, 0xea, 0x03, 0x00, 0x00}
	if got := singlePoint(1, 1002); !bytes.Equal(got, want) {
		t.Fatalf("single point % x, want % x", got, want)
	}
}

func TestReservedBitsRepeatsOnOneConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	wire := make(chan []byte, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		act := make([]byte, 6)
		if _, err := io.ReadFull(conn, act); err != nil || !bytes.Equal(act, startdtAct) {
			serverErr <- err
			return
		}
		if _, err := conn.Write(uFrame(0x0b)); err != nil { // STARTDT con
			serverErr <- err
			return
		}
		data, err := io.ReadAll(conn)
		wire <- data
		serverErr <- err
	}()
	r := run(options{addr: listener.Addr().String(), scenario: "reserved-bits", ca: 1, ioa: 2001, dcs: 2, repeat: 2, hold: 20 * time.Millisecond})
	if r.fatal != nil {
		t.Fatal(r.fatal)
	}
	want := iFrames(2, doubleCommand(1, 2001, 2, false), true)
	if got := <-wire; !bytes.Equal(got, want) || r.sent != len(want) {
		t.Fatalf("sent %d bytes, wire % x, want % x", r.sent, got, want)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if r.port == 0 {
		t.Fatalf("client port not reported")
	}
}
