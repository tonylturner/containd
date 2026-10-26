// SPDX-License-Identifier: Apache-2.0
//go:build linux

package engine

import (
	"encoding/binary"
	"math/rand/v2"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// TestStreamResyncKernelOutOfWindowRST runs in the first-command kernel
// lab (see first_command_kernel_linux_test.go for how to run it). After the
// head of a read, a RST at a random sequence number is sent on the
// client's connection; the server's stack ignores it. The crafted rest
// would complete the read and a prohibited write were the engine's stream
// restarted at it, so the server must receive neither.
func TestStreamResyncKernelOutOfWindowRST(t *testing.T) {
	ctx := newFirstCommandLab(t)
	srv := startModbusRecorder(t)
	startFirstCommandEngine(t, ctx)

	c := dialFirstCommand(ctx, t, "198.18.50.40")
	read := c.next(3, 0, 2)
	c.write(read[:8])
	local := c.conn.LocalAddr().(*net.TCPAddr)
	// One sequence number in 2^32 is the server's next one.
	rst := rawTCPSegment(local.IP, net.ParseIP(fcServerIP), uint16(local.Port), 502, rand.Uint32(), 0x04) // RST
	if err := inNetns(fcClientNS, func() error { return sendRaw(rst, net.ParseIP(fcServerIP)) }); err != nil {
		t.Fatalf("send RST: %v", err)
	}
	// Transaction ID 0x00FE: the misframed MBAP length field.
	c.write(append(read[8:], modbusADU(0x00FE, 6, 1, 0x1234)...))
	c.expectSilence()
	fcs, n, regs := srv.seen(c.src)
	if len(fcs) != 0 || n != 8 || regs != [8]uint16{} {
		t.Fatalf("server received FCs %v in %d bytes, registers %v; want only the 8-byte read head", fcs, n, regs)
	}
}

// rawTCPSegment is an IPv4 TCP segment without payload.
func rawTCPSegment(src, dst net.IP, sport, dport uint16, seq uint32, flags uint8) []byte {
	src4, dst4 := src.To4(), dst.To4()
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 1024)
	pseudo := append(append(append([]byte(nil), src4...), dst4...), 0, unix.IPPROTO_TCP, 0, byte(len(tcp)))
	binary.BigEndian.PutUint16(tcp[16:], inetChecksum(append(pseudo, tcp...)))
	ip := []byte{0x45, 0, 0, byte(20 + len(tcp)), 0, 0, 0, 0, 64, unix.IPPROTO_TCP, 0, 0}
	ip = append(append(ip, src4...), dst4...)
	binary.BigEndian.PutUint16(ip[10:], inetChecksum(ip))
	return append(ip, tcp...)
}

func inetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	return ^uint16(sum)
}

// sendRaw sends an IPv4 packet with its own header from this namespace.
func sendRaw(pkt []byte, dst net.IP) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	to := &unix.SockaddrInet4{}
	copy(to.Addr[:], dst.To4())
	return unix.Sendto(fd, pkt, 0, to)
}
