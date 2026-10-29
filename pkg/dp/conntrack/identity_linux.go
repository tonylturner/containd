// SPDX-License-Identifier: Apache-2.0

//go:build linux

package conntrack

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

type identityReader struct{ socket *querySocket }

// NewIdentityReader does no network I/O until Lookup.
func NewIdentityReader() IdentityReader { return &identityReader{} }

func (c *identityReader) Close() error {
	if c.socket == nil {
		return nil
	}
	err := unix.Close(c.socket.fd)
	c.socket = nil
	return err
}

func (c *identityReader) open() error {
	if c.socket != nil {
		return nil
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return err
	}
	c.socket = &querySocket{fd: fd, seq: uint32(time.Now().UnixNano()), buf: make([]byte, 64*1024)}
	return nil
}

// Lookup sends at most two exact selectors, never a dump. Failed exchanges
// retire the socket: late replies cannot become another lookup's evidence.
func (c *identityReader) Lookup(ctx context.Context, t Tuple) (Evidence, error) {
	if err := t.Validate(); err != nil {
		return Evidence{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Evidence{}, err
	}
	if err := c.open(); err != nil {
		return Evidence{}, err
	}
	for _, selector := range []uint16{1, 2} {
		payload, err := encodeIdentityLookup(t, selector)
		if err != nil {
			return Evidence{}, err
		}
		var evidence Evidence
		found := false
		err = c.socket.exchange(ctx, 0x101, payload, false, func(record []byte) (bool, error) {
			var err error
			evidence, err = decodeIdentity(record)
			found = err == nil
			return true, err
		})
		if err == nil && found {
			return evidence, evidence.Validate(t)
		}
		if err != nil && !errors.Is(err, unix.ENOENT) {
			_ = c.Close()
			return Evidence{}, err
		}
	}
	return Evidence{}, ErrNotFound
}

func encodeIdentityLookup(t Tuple, selector uint16) ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	if selector != 1 && selector != 2 {
		return nil, fmt.Errorf("invalid conntrack selector")
	}
	proto := "tcp"
	if t.Protocol == 17 {
		proto = "udp"
	}
	family, tuple, err := encodeTuple(DeleteRequest{Proto: proto,
		Src: t.Source.Addr().String(), Dst: t.Destination.Addr().String(),
		Sport: int(t.Source.Port()), Dport: int(t.Destination.Port())})
	if err != nil {
		return nil, err
	}
	out := append([]byte{family, 0, 0, 0}, nlAttr(selector|0x8000, tuple)...)
	return append(out, nlAttrU16(18, 0)...), nil
}

func decodeIdentity(record []byte) (Evidence, error) {
	var e Evidence
	if len(record) < 4 || record[1] != 0 {
		return e, fmt.Errorf("invalid conntrack identity header")
	}
	a, err := attributes(record[4:])
	if err != nil {
		return e, err
	}
	if e.Original, e.OriginalZone, err = decodeIdentityTuple(record[0], a[1]); err != nil {
		return e, err
	}
	if e.Reply, e.ReplyZone, err = decodeIdentityTuple(record[0], a[2]); err != nil {
		return e, err
	}
	if v, ok := a[18]; ok {
		if len(v) != 2 {
			return e, fmt.Errorf("invalid conntrack zone")
		}
		e.Zone = binary.BigEndian.Uint16(v)
	}
	if len(a[12]) != 4 || len(a[3]) != 4 || len(a[7]) != 4 {
		return e, fmt.Errorf("missing conntrack generation/status/timeout")
	}
	e.ID, e.Status, e.TimeoutSeconds = binary.BigEndian.Uint32(a[12]), binary.BigEndian.Uint32(a[3]), binary.BigEndian.Uint32(a[7])
	if v, ok := a[20]; ok {
		ts, err := attributes(v)
		if err != nil || len(ts[1]) != 8 {
			return e, fmt.Errorf("invalid conntrack start timestamp")
		}
		e.Start = binary.BigEndian.Uint64(ts[1])
	}
	return e, nil
}

func decodeIdentityTuple(family uint8, data []byte) (Tuple, uint16, error) {
	t, err := parseTuple(data)
	if err != nil {
		return Tuple{}, 0, err
	}
	proto := uint8(6)
	if t.proto == "udp" {
		proto = 17
	} else if t.proto != "tcp" {
		return Tuple{}, 0, fmt.Errorf("unsupported identity protocol")
	}
	src, err := netip.ParseAddr(t.src)
	if err != nil {
		return Tuple{}, 0, err
	}
	dst, err := netip.ParseAddr(t.dst)
	if err != nil {
		return Tuple{}, 0, err
	}
	sp, err := strconv.ParseUint(t.sport, 10, 16)
	if err != nil {
		return Tuple{}, 0, err
	}
	dp, err := strconv.ParseUint(t.dport, 10, 16)
	if err != nil {
		return Tuple{}, 0, err
	}
	out := Tuple{Family: family, Protocol: proto,
		Source: netip.AddrPortFrom(src, uint16(sp)), Destination: netip.AddrPortFrom(dst, uint16(dp))}
	a, err := attributes(data)
	if err != nil {
		return Tuple{}, 0, err
	}
	var zone uint16
	if v, ok := a[3]; ok {
		if len(v) != 2 {
			return Tuple{}, 0, fmt.Errorf("invalid directional conntrack zone")
		}
		zone = binary.BigEndian.Uint16(v)
	}
	return out, zone, out.Validate()
}
