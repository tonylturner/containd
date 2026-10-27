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
	family, tuple, err := encodeTuple(req)
	if err != nil {
		return err
	}
	payload := append([]byte{family, 0, 0, 0}, nlAttr(1|0x8000, tuple)...)
	return exchange(ctx, 0x102, payload, false, nil)
}

// encodeTuple returns the address family and CTA_TUPLE_ORIG nest content of
// req: ports for TCP and UDP, identifier, type and code for ICMP and ICMPv6.
func encodeTuple(req DeleteRequest) (byte, []byte, error) {
	proto, err := protoToNum(req.Proto)
	if err != nil {
		return 0, nil, err
	}
	src, dst := net.ParseIP(strings.TrimSpace(req.Src)), net.ParseIP(strings.TrimSpace(req.Dst))
	if src == nil || dst == nil || (src.To4() == nil) != (dst.To4() == nil) {
		return 0, nil, fmt.Errorf("conntrack delete: invalid or mixed-family endpoints")
	}
	family := byte(unix.AF_INET6)
	srcType, dstType := uint16(3), uint16(4)
	if src.To4() != nil {
		family = unix.AF_INET
		src, dst = src.To4(), dst.To4()
		srcType, dstType = 1, 2
	}
	ip := append(nlAttr(srcType, src), nlAttr(dstType, dst)...)
	p := nlAttr(ctaProtoNum, []byte{proto})
	if attrs, ok := icmpAttrs[proto]; ok {
		if req.ICMPID < 0 || req.ICMPID > 65535 || req.ICMPType < 0 || req.ICMPType > 255 || req.ICMPCode < 0 || req.ICMPCode > 255 {
			return 0, nil, fmt.Errorf("conntrack delete: icmp identifier, type or code out of range")
		}
		p = append(p, nlAttrU16(attrs[0], uint16(req.ICMPID))...)
		p = append(p, nlAttr(attrs[1], []byte{byte(req.ICMPType)})...)
		p = append(p, nlAttr(attrs[2], []byte{byte(req.ICMPCode)})...)
	} else {
		if req.Sport < 0 || req.Sport > 65535 || req.Dport < 0 || req.Dport > 65535 {
			return 0, nil, fmt.Errorf("conntrack delete: ports out of range")
		}
		p = append(p, nlAttrU16(ctaProtoSrcPort, uint16(req.Sport))...)
		p = append(p, nlAttrU16(ctaProtoDstPort, uint16(req.Dport))...)
	}
	return family, append(nlAttr(1|0x8000, ip), nlAttr(2|0x8000, p)...), nil
}

func protoToNum(p string) (byte, error) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	case "icmp":
		return 1, nil
	case "icmpv6":
		return 58, nil
	default:
		return 0, fmt.Errorf("conntrack delete: unsupported proto %q", p)
	}
}
