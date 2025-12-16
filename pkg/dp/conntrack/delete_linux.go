//go:build linux

package conntrack

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Delete removes a conntrack entry matching the provided 5-tuple (IPv4 only for now).
// This is best-effort and primarily intended for operator "kill session" actions.
func Delete(ctx context.Context, req DeleteRequest) error {
	protoNum, err := protoToNum(req.Proto)
	if err != nil {
		return err
	}
	src := net.ParseIP(strings.TrimSpace(req.Src))
	dst := net.ParseIP(strings.TrimSpace(req.Dst))
	if src == nil || dst == nil {
		return errors.New("conntrack delete: src/dst must be valid IPs")
	}
	src4 := src.To4()
	dst4 := dst.To4()
	if src4 == nil || dst4 == nil {
		return errors.New("conntrack delete: IPv6 not supported yet")
	}
	if req.Sport < 0 || req.Sport > 65535 || req.Dport < 0 || req.Dport > 65535 {
		return errors.New("conntrack delete: ports out of range")
	}

	// Constants mirrored from linux netfilter headers (minimal subset).
	const (
		nlaFNested = 1 << 15

		nfnlSubsysCTnetlink = 1
		ipctnlMsgCtDelete   = 2

		ctaTupleOrig  = 1
		ctaTupleIP    = 1
		ctaTupleProto = 2

		ctaIPV4Src = 1
		ctaIPV4Dst = 2

		ctaProtoNum     = 1
		ctaProtoSrcPort = 2
		ctaProtoDstPort = 3
	)

	// nfgenmsg header: family, version, res_id
	nfgen := make([]byte, 4)
	nfgen[0] = unix.AF_INET
	nfgen[1] = 0 // NFNETLINK_V0
	binary.BigEndian.PutUint16(nfgen[2:4], 0)

	ipAttrs := append(
		nlAttr(ctaIPV4Src, []byte(src4)),
		nlAttr(ctaIPV4Dst, []byte(dst4))...,
	)
	protoAttrs := append(
		nlAttr(ctaProtoNum, []byte{byte(protoNum)}),
		nlAttrU16(ctaProtoSrcPort, uint16(req.Sport))...,
	)
	protoAttrs = append(protoAttrs, nlAttrU16(ctaProtoDstPort, uint16(req.Dport))...)

	tuple := nlAttr(ctaTupleIP|nlaFNested, ipAttrs)
	tuple = append(tuple, nlAttr(ctaTupleProto|nlaFNested, protoAttrs)...)

	attrs := nlAttr(ctaTupleOrig|nlaFNested, tuple)

	payload := append(nfgen, attrs...)

	nlType := uint16((nfnlSubsysCTnetlink << 8) | ipctnlMsgCtDelete)
	return netfilterRequest(ctx, nlType, payload)
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

func nlAlign4(n int) int { return (n + 3) &^ 3 }

func nlAttr(typ uint16, value []byte) []byte {
	l := 4 + len(value)
	padded := nlAlign4(l)
	b := make([]byte, padded)
	binary.LittleEndian.PutUint16(b[0:2], uint16(l))
	binary.LittleEndian.PutUint16(b[2:4], typ)
	copy(b[4:4+len(value)], value)
	return b
}

func nlAttrU16(typ uint16, v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return nlAttr(typ, b)
}

func netfilterRequest(ctx context.Context, msgType uint16, payload []byte) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("conntrack delete: netlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("conntrack delete: netlink bind: %w", err)
	}

	seq := uint32(time.Now().UnixNano())
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(16+len(payload)))
	binary.LittleEndian.PutUint16(hdr[4:6], msgType)
	binary.LittleEndian.PutUint16(hdr[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.LittleEndian.PutUint32(hdr[8:12], seq)
	binary.LittleEndian.PutUint32(hdr[12:16], 0)

	msg := append(hdr, payload...)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("conntrack delete: netlink send: %w", err)
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(2 * time.Second)
	}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{
		Sec:  int64(time.Until(deadline) / time.Second),
		Usec: int64((time.Until(deadline) % time.Second) / time.Microsecond),
	})

	buf := make([]byte, 8192)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return fmt.Errorf("conntrack delete: netlink timeout")
			}
			return fmt.Errorf("conntrack delete: netlink recv: %w", err)
		}
		if n < 16 {
			continue
		}
		nlmsgType := binary.LittleEndian.Uint16(buf[4:6])
		nlmsgSeq := binary.LittleEndian.Uint32(buf[8:12])
		if nlmsgSeq != seq {
			continue
		}
		if nlmsgType != unix.NLMSG_ERROR {
			// ignore multi-part noise
			continue
		}
		if n < 16+4 {
			return fmt.Errorf("conntrack delete: short NLMSG_ERROR")
		}
		errno := int32(binary.LittleEndian.Uint32(buf[16 : 16+4]))
		if errno == 0 {
			return nil
		}
		// Kernel returns negative errno.
		e := unix.Errno(-errno)
		if e == unix.ENOENT {
			return fmt.Errorf("conntrack delete: not found")
		}
		return fmt.Errorf("conntrack delete: %w", e)
	}
}

