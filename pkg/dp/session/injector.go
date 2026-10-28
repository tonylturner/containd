// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

// Package session sends TCP resets for aborted sessions. It knows TCP
// tuples and sequence numbers, not policy.
package session

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
)

// Reset describes one payload-free IPv4 RST. It is sent with source Src to
// Dst, so Src is spoofed as the peer of the endpoint being reset.
type Reset struct {
	Src, Dst netip.AddrPort
	Seq      uint32
}

// Injector sends TCP resets.
type Injector interface {
	// SendRST sends one payload-free IPv4 RST with route-selected egress.
	// nil means the socket accepted it, not that the endpoint closed.
	SendRST(r Reset) error
	Close() error
}

// ErrUnsupportedPlatform reports that raw RST injection is unavailable.
var ErrUnsupportedPlatform = errors.New("session: raw TCP reset injection is not supported on this platform")

// rstLen is the length of a payload-free IPv4+TCP reset: two 20-byte
// headers without options.
const rstLen = 40

// buildRST returns the IPv4 packet for r: a payload-free TCP segment with
// only RST set, sequence r.Seq, window 0, TTL 64, and both checksums.
func buildRST(r Reset) ([]byte, error) {
	src, dst := r.Src.Addr().Unmap(), r.Dst.Addr().Unmap()
	if !src.Is4() || !dst.Is4() {
		return nil, fmt.Errorf("session: reset %s -> %s: only IPv4 is supported", r.Src, r.Dst)
	}
	if r.Src.Port() == 0 || r.Dst.Port() == 0 {
		return nil, fmt.Errorf("session: reset %s -> %s: port 0", r.Src, r.Dst)
	}
	pkt := make([]byte, rstLen)
	ip := pkt[:20]
	ip[0] = 0x45 // IPv4, 20-byte header
	binary.BigEndian.PutUint16(ip[2:4], rstLen)
	ip[8] = 64 // TTL
	ip[9] = syscall.IPPROTO_TCP
	s4, d4 := src.As4(), dst.As4()
	copy(ip[12:16], s4[:])
	copy(ip[16:20], d4[:])
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip, 0))

	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:2], r.Src.Port())
	binary.BigEndian.PutUint16(tcp[2:4], r.Dst.Port())
	binary.BigEndian.PutUint32(tcp[4:8], r.Seq)
	tcp[12] = 5 << 4 // data offset: 20 bytes
	tcp[13] = flagRST
	binary.BigEndian.PutUint16(tcp[16:18], checksum(tcp, pseudoHeaderSum(s4, d4, len(tcp))))
	return pkt, nil
}

const (
	flagRST = 0x04
)

// pseudoHeaderSum is the unfolded one's-complement sum of the IPv4 TCP
// pseudo-header.
func pseudoHeaderSum(src, dst [4]byte, tcpLen int) uint32 {
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(src[0:2])) + uint32(binary.BigEndian.Uint16(src[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst[0:2])) + uint32(binary.BigEndian.Uint16(dst[2:4]))
	sum += uint32(syscall.IPPROTO_TCP) + uint32(tcpLen)
	return sum
}

// checksum is the Internet checksum (RFC 1071) of data, seeded with an
// unfolded partial sum.
func checksum(data []byte, seed uint32) uint16 {
	sum := seed
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
