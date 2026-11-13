// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

var ports = map[string]int{"modbus": 502, "dnp3": 20000, "iec104": 2404}

type session struct {
	conn      net.Conn
	protocol  string
	tx, rx    uint16
	transport byte
}

func writeMessage(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func crc(b []byte) uint16 {
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
	return ^c
}
func dnpFrame(body []byte, reply bool) []byte {
	h := []byte{5, 0x64, byte(5 + len(body)), 0xc4, 1, 0, 0, 4}
	if reply {
		h[3] = 0x44
		h[4], h[5], h[6], h[7] = 0, 4, 1, 0
	}
	h = binary.LittleEndian.AppendUint16(h, crc(h))
	for len(body) > 0 {
		n := min(16, len(body))
		h = append(h, body[:n]...)
		h = binary.LittleEndian.AppendUint16(h, crc(body[:n]))
		body = body[n:]
	}
	return h
}
func readDNP(r io.Reader, reply bool) ([]byte, int, error) {
	h := make([]byte, 10)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, 0, err
	}
	if h[0] != 5 || h[1] != 0x64 || h[2] < 5 || crc(h[:8]) != binary.LittleEndian.Uint16(h[8:]) {
		return nil, 0, fmt.Errorf("DNP3 link header/CRC")
	}
	control := byte(0xc4)
	dest, src := uint16(1), uint16(1024)
	if reply {
		control = 0x44
		dest, src = src, dest
	}
	if h[3] != control || binary.LittleEndian.Uint16(h[4:]) != dest || binary.LittleEndian.Uint16(h[6:]) != src {
		return nil, 0, fmt.Errorf("DNP3 addresses/control")
	}
	left := int(h[2]) - 5
	body := make([]byte, 0, left)
	wire := 10
	for left > 0 {
		n := min(16, left)
		block := make([]byte, n+2)
		if _, err := io.ReadFull(r, block); err != nil {
			return nil, wire, err
		}
		if crc(block[:n]) != binary.LittleEndian.Uint16(block[n:]) {
			return nil, wire, fmt.Errorf("DNP3 data CRC")
		}
		body = append(body, block[:n]...)
		left -= n
		wire += n + 2
	}
	return body, wire, nil
}
func readIEC(r io.Reader) ([]byte, error) {
	h := make([]byte, 2)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, err
	}
	if h[0] != 0x68 || h[1] < 4 || h[1] > 253 {
		return nil, fmt.Errorf("IEC104 framing")
	}
	b := make([]byte, int(h[1])+2)
	copy(b, h)
	_, err := io.ReadFull(r, b[2:])
	return b, err
}
func iFrame(tx, rx uint16, asdu []byte) []byte {
	b := []byte{0x68, byte(4 + len(asdu)), 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(b[2:], tx<<1)
	binary.LittleEndian.PutUint16(b[4:], rx<<1)
	return append(b, asdu...)
}

var iecRead = []byte{102, 1, 5, 0, 1, 0, 1, 0, 0}
var iecReply = []byte{1, 1, 5, 0, 1, 0, 1, 0, 0, 1}

func (s *session) init(peer bool) error {
	if s.protocol != "iec104" {
		return nil
	}
	if peer {
		b, err := readIEC(s.conn)
		if err != nil {
			return err
		}
		if !bytes.Equal(b, []byte{0x68, 4, 7, 0, 0, 0}) {
			return fmt.Errorf("IEC104 STARTDT act")
		}
		return writeMessage(s.conn, []byte{0x68, 4, 0x0b, 0, 0, 0})
	}
	if err := writeMessage(s.conn, []byte{0x68, 4, 7, 0, 0, 0}); err != nil {
		return err
	}
	b, err := readIEC(s.conn)
	if err != nil {
		return err
	}
	if !bytes.Equal(b, []byte{0x68, 4, 0x0b, 0, 0, 0}) {
		return fmt.Errorf("IEC104 STARTDT con")
	}
	return nil
}
func (s *session) exchange(peer bool) (int, int, error) {
	switch s.protocol {
	case "modbus":
		return s.modbus(peer)
	case "dnp3":
		return s.dnp(peer)
	case "iec104":
		return s.iec(peer)
	default:
		return 0, 0, fmt.Errorf("unknown protocol %q", s.protocol)
	}
}
func (s *session) modbus(peer bool) (int, int, error) {
	req := []byte{0, 0, 0, 0, 0, 6, 1, 3, 0, 0, 0, 2}
	binary.BigEndian.PutUint16(req, s.tx)
	rep := []byte{0, 0, 0, 0, 0, 7, 1, 3, 4, 0, 1, 0, 2}
	binary.BigEndian.PutUint16(rep, s.tx)
	if peer {
		b := make([]byte, len(req))
		if _, err := io.ReadFull(s.conn, b); err != nil {
			return 0, 0, err
		}
		if !bytes.Equal(b, req) {
			return 0, 0, fmt.Errorf("modbus request/TID/FC3")
		}
		if err := writeMessage(s.conn, rep); err != nil {
			return 0, 0, err
		}
	} else {
		if err := writeMessage(s.conn, req); err != nil {
			return 0, 0, err
		}
		b := make([]byte, len(rep))
		if _, err := io.ReadFull(s.conn, b); err != nil {
			return 0, 0, err
		}
		if !bytes.Equal(b, rep) {
			return 0, 0, fmt.Errorf("modbus response/TID/registers")
		}
	}
	s.tx++
	return len(req), len(rep), nil
}
func (s *session) dnp(peer bool) (int, int, error) {
	app := byte(s.tx&15) | 0xc0
	transport := s.transport&63 | 0xc0
	req := []byte{transport, app, 1, 60, 1, 6}
	rep := []byte{transport, app, 0x81, 0, 0, 1, 2, 0, 0, 0, 0x81}
	if peer {
		b, _, err := readDNP(s.conn, false)
		if err != nil {
			return 0, 0, err
		}
		if !bytes.Equal(b, req) {
			return 0, 0, fmt.Errorf("DNP3 class-0 request/sequence")
		}
		if err := writeMessage(s.conn, dnpFrame(rep, true)); err != nil {
			return 0, 0, err
		}
	} else {
		if err := writeMessage(s.conn, dnpFrame(req, false)); err != nil {
			return 0, 0, err
		}
		b, _, err := readDNP(s.conn, true)
		if err != nil {
			return 0, 0, err
		}
		if !bytes.Equal(b, rep) {
			return 0, 0, fmt.Errorf("DNP3 response/sequence/IIN/object")
		}
	}
	s.tx++
	s.transport++
	return len(dnpFrame(req, false)), len(dnpFrame(rep, true)), nil
}
func (s *session) iec(peer bool) (int, int, error) {
	req := iFrame(s.tx, s.rx, iecRead)
	rep := iFrame(s.rx, (s.tx+1)&0x7fff, iecReply)
	if peer {
		b, err := readIEC(s.conn)
		if err != nil {
			return 0, 0, err
		}
		if !bytes.Equal(b, req) {
			return 0, 0, fmt.Errorf("IEC104 read/sequence/ack")
		}
		if err := writeMessage(s.conn, rep); err != nil {
			return 0, 0, err
		}
		ack, err := readIEC(s.conn)
		if err != nil {
			return 0, 0, err
		}
		want := []byte{0x68, 4, 1, 0, 0, 0}
		binary.LittleEndian.PutUint16(want[4:], ((s.rx+1)&0x7fff)<<1)
		if !bytes.Equal(ack, want) {
			return 0, 0, fmt.Errorf("IEC104 S acknowledgement")
		}
	} else {
		if err := writeMessage(s.conn, req); err != nil {
			return 0, 0, err
		}
		b, err := readIEC(s.conn)
		if err != nil {
			return 0, 0, err
		}
		if !bytes.Equal(b, rep) {
			return 0, 0, fmt.Errorf("IEC104 response/sequence/ack/value")
		}
		ack := []byte{0x68, 4, 1, 0, 0, 0}
		binary.LittleEndian.PutUint16(ack[4:], ((s.rx+1)&0x7fff)<<1)
		if err := writeMessage(s.conn, ack); err != nil {
			return 0, 0, err
		}
	}
	s.tx = (s.tx + 1) & 0x7fff
	s.rx = (s.rx + 1) & 0x7fff
	return len(req), len(rep), nil
}
