// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package conntrack

import (
	"context"
	"fmt"
	"net"
	"strings"

	"golang.org/x/sys/unix"
)

// Delete removes the kernel entry using its original tuple. Callers operating on
// a listed entry must use that tuple, not a post-NAT packet's addresses.
func Delete(ctx context.Context, req DeleteRequest) error {
	proto, err := protoToNum(req.Proto)
	if err != nil {
		return err
	}
	src, dst := net.ParseIP(strings.TrimSpace(req.Src)), net.ParseIP(strings.TrimSpace(req.Dst))
	if src == nil || dst == nil || (src.To4() == nil) != (dst.To4() == nil) {
		return fmt.Errorf("conntrack delete: invalid or mixed-family endpoints")
	}
	if req.Sport < 0 || req.Sport > 65535 || req.Dport < 0 || req.Dport > 65535 {
		return fmt.Errorf("conntrack delete: ports out of range")
	}
	family := byte(unix.AF_INET6)
	srcType, dstType := uint16(3), uint16(4)
	if src.To4() != nil {
		family = unix.AF_INET
		src, dst = src.To4(), dst.To4()
		srcType, dstType = 1, 2
	}
	ip := append(nlAttr(srcType, src), nlAttr(dstType, dst)...)
	p := nlAttr(1, []byte{byte(proto)})
	p = append(p, nlAttrU16(2, uint16(req.Sport))...)
	p = append(p, nlAttrU16(3, uint16(req.Dport))...)
	tuple := append(nlAttr(1|0x8000, ip), nlAttr(2|0x8000, p)...)
	payload := append([]byte{family, 0, 0, 0}, nlAttr(1|0x8000, tuple)...)
	return exchange(ctx, 0x102, payload, false, nil)
}
func protoToNum(p string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	case "icmp":
		return 1, nil
	default:
		return 0, fmt.Errorf("conntrack delete: unsupported proto %q", p)
	}
}
