// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

// Command malformer is an Apache-2.0, pure-Go IEC 60870-5-104 test client for
// the containd truth harness. It hand-builds APDU bytes so the
// harness can drive malformed, unsupported, split and coalesced cases that a
// conforming stack (lib60870) will not emit. It never links lib60870.
//
// It opens one TCP connection, optionally completes the APCI handshake
// (STARTDT act, wait for con), then writes a named scenario's bytes — whole,
// split into small segments, or several APDUs coalesced into one segment — and
// reports what it observed. Exit 0 means the scenario ran and its send
// expectation held; non-zero means a connection or expectation failure. The
// harness judges prevention from the firewall and the RTU state, not from
// this tool's exit code alone.
//
// Scenarios (see test/iec104/README.md for the wire layout of each):
//
//	startdt            APCI STARTDT act only
//	gi                 STARTDT act, then a station GI (type 100) request
//	dc-select          a valid type 46 double-command SELECT to CA/IOA/value
//	dc-execute         a valid type 46 double-command EXECUTE to CA/IOA/value
//	dc-split           a dc-select written in -chunk byte segments, -gap-ms apart
//	coalesced          a GI request and a dc-execute in one TCP segment
//	truncated-apdu     an I-frame whose length octet (20) exceeds the 10 octets
//	                   that follow; the connection then closes (FIN), so the
//	                   APDU is truncated, not merely incomplete
//	bad-length         after STARTDT, an APCI whose length octet is 2 (below
//	                   the minimum of 4): a framing violation
//	malformed-dcs      a type 46 command with the illegal DCS value 3
//	unsupported-type   an I-frame with Type ID 104 (not used in IEC 104),
//	                   sent without STARTDT
//	stale-retransmit   (Linux only) a raw-socket TCP session that sends a
//	                   forbidden command, then, after a second handshake from
//	                   another port, injects a later segment of the first
//	                   session (its old ISN and next sequence) carrying a fresh
//	                   forbidden command. Reports whether that stale segment
//	                   reached the RTU. -ioa is the forbidden point.
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"
)

const (
	startByte      = 0x68
	defaultTimeout = 4 * time.Second
)

// apci builds a 6-byte APCI U-frame with the given control octet 1.
func uFrame(control1 byte) []byte {
	return []byte{startByte, 0x04, control1, 0x00, 0x00, 0x00}
}

var (
	startdtAct = uFrame(0x07)
)

// iFrame builds an I-frame carrying asdu, with send/recv sequence numbers 0.
// The length octet counts the four control octets plus the ASDU.
func iFrame(ns, nr uint16, asdu []byte) []byte {
	frame := make([]byte, 0, 6+len(asdu))
	length := 4 + len(asdu)
	frame = append(frame, startByte, byte(length))
	frame = append(frame, byte(ns<<1), byte(ns>>7))
	frame = append(frame, byte(nr<<1), byte(nr>>7))
	frame = append(frame, asdu...)
	return frame
}

// asduHeader builds a single-object ASDU header: Type ID, VSQ (SQ=0, count=1),
// COT (2 octets: cause + originator), CA (2 octets, little-endian).
func asduHeader(typeID byte, cot byte, ca uint16) []byte {
	h := []byte{typeID, 0x01, cot, 0x00}
	h = binary.LittleEndian.AppendUint16(h, ca)
	return h
}

func ioa3(ioa uint32) []byte {
	return []byte{byte(ioa), byte(ioa >> 8), byte(ioa >> 16)}
}

// doubleCommand builds a C_DC_NA_1 (type 46) single-object ASDU. dcs is the
// two-bit command (1=open, 2=close); sel sets the select bit; qu is 0.
func doubleCommand(ca uint16, ioa uint32, dcs byte, sel bool) []byte {
	asdu := asduHeader(46, 6 /* activation */, ca)
	asdu = append(asdu, ioa3(ioa)...)
	dco := dcs & 0x03
	if sel {
		dco |= 0x80
	}
	return append(asdu, dco)
}

// interrogation builds a C_IC_NA_1 (type 100) station GI request at IOA 0.
func interrogation(ca uint16) []byte {
	asdu := asduHeader(100, 6, ca)
	asdu = append(asdu, ioa3(0)...)
	return append(asdu, 20) // QOI = station
}

// checksum16 is the one's-complement Internet checksum of b.
func checksum16(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildIPv4TCP assembles one IPv4 TCP segment with both checksums filled in.
// IP options are not used; flags is the TCP flag octet (see TCP* below).
func buildIPv4TCP(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags byte, window uint16, payload []byte) []byte {
	const ipHdr, tcpHdr = 20, 20
	total := ipHdr + tcpHdr + len(payload)

	ip := make([]byte, ipHdr)
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:], uint16(total))
	ip[8] = 64 // TTL
	ip[9] = 6  // TCP
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	binary.BigEndian.PutUint16(ip[10:], checksum16(ip))

	tcp := make([]byte, tcpHdr+len(payload))
	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], dstPort)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = tcpHdr / 4 << 4 // data offset, no options
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], window)
	copy(tcp[tcpHdr:], payload)

	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], srcIP[:])
	copy(pseudo[4:8], dstIP[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	binary.BigEndian.PutUint16(tcp[16:], checksum16(pseudo))

	return append(ip, tcp...)
}

// seqGreater reports a > b in 32-bit TCP sequence space (modular comparison).
func seqGreater(a, b uint32) bool {
	return int32(a-b) > 0
}

// TCP flag octet bits.
const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpPSH = 0x08
	tcpACK = 0x10
)

type result struct {
	name   string
	sent   int
	note   string
	socket string
	fatal  error
}

// options are the command-line parameters of one scenario run.
type options struct {
	addr     string
	scenario string
	ca       uint16
	ioa      uint32
	dcs      int
	chunk    int
	gapMS    int
	lport    int
	hold     time.Duration
}

// dial connects to addr, from local port lport when it is non-zero. The
// harness reuses a port to test that a same-5-tuple reconnect cannot bypass an
// abort; SO_REUSEADDR lets the bind succeed while the old socket lingers.
func dial(addr string, lport int) (net.Conn, error) {
	dialer := net.Dialer{Timeout: defaultTimeout}
	if lport > 0 {
		dialer.LocalAddr = &net.TCPAddr{Port: lport}
		dialer.Control = func(_, _ string, raw syscall.RawConn) error {
			var sockErr error
			if err := raw.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			}); err != nil {
				return err
			}
			return sockErr
		}
	}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(defaultTimeout))
	return conn, nil
}

// observe reads until the peer closes or resets the connection or hold
// elapses, and classifies the client socket: reset (RST received), eof (FIN
// received) or open (still established when hold ended).
func observe(conn net.Conn, hold time.Duration) (string, int) {
	_ = conn.SetDeadline(time.Now().Add(hold))
	buf := make([]byte, 4096)
	total := 0
	for {
		n, err := conn.Read(buf)
		total += n
		switch {
		case err == nil:
			continue
		case errors.Is(err, syscall.ECONNRESET):
			return "reset", total
		case errors.Is(err, io.EOF):
			return "eof", total
		default:
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return "open", total
			}
			return "error:" + err.Error(), total
		}
	}
}

// handshake sends STARTDT act and waits for any APCI reply (STARTDT con).
func handshake(conn net.Conn) error {
	if _, err := conn.Write(startdtAct); err != nil {
		return err
	}
	buf := make([]byte, 6)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("no STARTDT con: %w", err)
	}
	return nil
}

func writeAll(conn net.Conn, data []byte) (int, error) {
	return conn.Write(data)
}

// writeSplit sends data in chunk-sized segments with a gap between them, so
// the firewall sees a single APDU arrive across several packets. chunk <= 0
// means one byte per segment.
func writeSplit(conn net.Conn, data []byte, chunk int, gap time.Duration) (int, error) {
	if chunk <= 0 {
		chunk = 1
	}
	total := 0
	for off := 0; off < len(data); off += chunk {
		end := off + chunk
		if end > len(data) {
			end = len(data)
		}
		n, err := conn.Write(data[off:end])
		total += n
		if err != nil {
			return total, err
		}
		if end < len(data) {
			time.Sleep(gap)
		}
	}
	return total, nil
}

func run(o options) result {
	scenario, ca, ioa, dcs, chunk := o.scenario, o.ca, o.ioa, o.dcs, o.chunk
	if scenario == "stale-retransmit" {
		return staleRetransmit(o)
	}
	r := result{name: scenario}
	conn, err := dial(o.addr, o.lport)
	if err != nil {
		r.fatal = fmt.Errorf("dial: %w", err)
		return r
	}
	defer conn.Close()

	gap := time.Duration(o.gapMS) * time.Millisecond

	switch scenario {
	case "startdt":
		r.sent, r.fatal = writeAll(conn, startdtAct)
	case "gi":
		if err := handshake(conn); err != nil {
			r.fatal = err
			return r
		}
		r.sent, r.fatal = writeAll(conn, iFrame(0, 0, interrogation(ca)))
	case "dc-select":
		if err := handshake(conn); err != nil {
			r.fatal = err
			return r
		}
		r.sent, r.fatal = writeAll(conn, iFrame(0, 0, doubleCommand(ca, ioa, byte(dcs), true)))
	case "dc-execute":
		if err := handshake(conn); err != nil {
			r.fatal = err
			return r
		}
		r.sent, r.fatal = writeAll(conn, iFrame(0, 0, doubleCommand(ca, ioa, byte(dcs), false)))
	case "dc-split":
		// A forbidden SELECT split across segments: if it reassembles at
		// the RTU it is recorded in the RTU state, so the harness sees receipt.
		if err := handshake(conn); err != nil {
			r.fatal = err
			return r
		}
		r.note = fmt.Sprintf("%d-byte segments", chunk)
		r.sent, r.fatal = writeSplit(conn, iFrame(0, 0, doubleCommand(ca, ioa, byte(dcs), true)), chunk, gap)
	case "coalesced":
		if err := handshake(conn); err != nil {
			r.fatal = err
			return r
		}
		combined := append(iFrame(0, 0, interrogation(ca)), iFrame(1, 0, doubleCommand(ca, ioa, byte(dcs), false))...)
		r.note = "GI + dc-execute in one segment"
		r.sent, r.fatal = writeAll(conn, combined)
	case "truncated-apdu":
		// Length octet claims 20 payload octets but only the ASDU header
		// follows: a layout violation, not an incomplete frame.
		asdu := asduHeader(46, 6, ca)
		frame := []byte{startByte, 0x14, 0x00, 0x00, 0x00, 0x00}
		frame = append(frame, asdu...)
		r.note = "length octet exceeds payload"
		r.sent, r.fatal = writeAll(conn, frame)
	case "bad-length":
		if err := handshake(conn); err != nil {
			r.fatal = err
			return r
		}
		r.note = "length octet 2"
		r.sent, r.fatal = writeAll(conn, []byte{startByte, 0x02, 0x01, 0x00})
	case "malformed-dcs":
		if err := handshake(conn); err != nil {
			r.fatal = err
			return r
		}
		r.note = "DCS=3 (illegal double command)"
		r.sent, r.fatal = writeAll(conn, iFrame(0, 0, doubleCommand(ca, ioa, 3, false)))
	case "unsupported-type":
		// Type ID 104 (C_RD_NA_1 / IEC-101 test) is not used in 104; B
		// reports it unsupported. Sent without a handshake on purpose.
		asdu := asduHeader(104, 6, ca)
		asdu = append(asdu, ioa3(ioa)...)
		r.note = "Type ID 104"
		r.sent, r.fatal = writeAll(conn, iFrame(0, 0, asdu))
	default:
		r.fatal = fmt.Errorf("unknown scenario %q", scenario)
		return r
	}

	if r.fatal != nil {
		return r
	}
	// Read replies (so a confirmation shows in a capture) and classify how the
	// connection ended; with -hold 0 this is a short drain.
	hold := o.hold
	if hold <= 0 {
		hold = 500 * time.Millisecond
	}
	var received int
	r.socket, received = observe(conn, hold)
	if received > 0 {
		r.note += fmt.Sprintf(" (reply %d bytes)", received)
	}
	return r
}

func main() {
	addr := flag.String("addr", "", "RTU address host:port")
	scenario := flag.String("scenario", "", "scenario name")
	ca := flag.Uint("ca", 1, "common address")
	ioa := flag.Uint("ioa", 2001, "information object address")
	dcs := flag.Int("dcs", 2, "double command value (1=open, 2=close)")
	chunk := flag.Int("chunk", 4, "segment size in bytes for split sends")
	gapMS := flag.Int("gap-ms", 20, "gap between segments for split sends")
	lport := flag.Int("lport", 0, "local TCP port to bind (0 = ephemeral)")
	hold := flag.Duration("hold", 0, "after sending, wait up to this long for the peer to close or reset")
	flag.Parse()

	if *addr == "" || *scenario == "" {
		fmt.Fprintln(os.Stderr, "usage: malformer -addr host:port -scenario NAME [-ca N -ioa N -dcs N -chunk N -gap-ms N -lport N -hold DURATION]")
		os.Exit(2)
	}

	r := run(options{
		addr: *addr, scenario: *scenario, ca: uint16(*ca), ioa: uint32(*ioa),
		dcs: *dcs, chunk: *chunk, gapMS: *gapMS, lport: *lport, hold: *hold,
	})
	if r.fatal != nil {
		fmt.Fprintf(os.Stderr, "%s: FAILED: %v\n", r.name, r.fatal)
		os.Exit(1)
	}
	// The last field is machine-read by scripts/smoke-iec104.sh.
	fmt.Printf("%s: sent %d bytes %s client_socket=%s\n", r.name, r.sent, r.note, r.socket)
}
