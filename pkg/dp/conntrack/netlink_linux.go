// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package conntrack

import (
	"context"
	"encoding/binary"
	"fmt"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func nlAlign4(n int) int { return (n + 3) &^ 3 }
func nlAttr(typ uint16, value []byte) []byte {
	b := make([]byte, nlAlign4(4+len(value)))
	binary.NativeEndian.PutUint16(b, uint16(4+len(value)))
	binary.NativeEndian.PutUint16(b[2:], typ)
	copy(b[4:], value)
	return b
}
func nlAttrU16(typ uint16, v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return nlAttr(typ, b)
}

// exchange drains the entire dump, even when the caller only wants its first
// records. An interrupted dump is never presented as a verified empty table.
func exchange(ctx context.Context, typ uint16, payload []byte, dump bool) ([][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("ctnetlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("ctnetlink bind: %w", err)
	}
	seq := uint32(time.Now().UnixNano())
	msg := make([]byte, 16+len(payload))
	binary.NativeEndian.PutUint32(msg, uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:], typ)
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK)
	if dump {
		flags = unix.NLM_F_REQUEST | unix.NLM_F_DUMP
	}
	binary.NativeEndian.PutUint16(msg[6:], flags)
	binary.NativeEndian.PutUint32(msg[8:], seq)
	copy(msg[16:], payload)
	if err = unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("ctnetlink send: %w", err)
	}
	out := [][]byte{}
	buf := make([]byte, 1<<20)
	for {
		if err = ctx.Err(); err != nil {
			return nil, fmt.Errorf("ctnetlink receive: %w", err)
		}
		ready := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if _, err = unix.Poll(ready, 50); err == unix.EINTR {
			continue
		} else if err != nil {
			return nil, err
		}
		n, _, recvFlags, from, err := unix.Recvmsg(fd, buf, nil, unix.MSG_DONTWAIT)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("ctnetlink receive: %w", err)
		}
		if recvFlags&unix.MSG_TRUNC != 0 {
			return nil, fmt.Errorf("ctnetlink truncated datagram")
		}
		sender, ok := from.(*unix.SockaddrNetlink)
		if !ok || sender.Pid != 0 {
			return nil, fmt.Errorf("ctnetlink unexpected sender")
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, fmt.Errorf("ctnetlink messages: %w", err)
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue
			}
			if m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				return nil, fmt.Errorf("conntrack dump interrupted")
			}
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				if len(m.Data) >= 4 && int32(binary.NativeEndian.Uint32(m.Data)) != 0 {
					return nil, fmt.Errorf("ctnetlink dump: %w", unix.Errno(-int32(binary.NativeEndian.Uint32(m.Data))))
				}
				return out, nil
			case unix.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return nil, fmt.Errorf("ctnetlink short acknowledgement")
				}
				code := int32(binary.NativeEndian.Uint32(m.Data))
				if code != 0 {
					return nil, fmt.Errorf("ctnetlink: %w", unix.Errno(-code))
				}
				if !dump {
					return out, nil
				}
			default:
				out = append(out, append([]byte(nil), m.Data...))
			}
		}
	}
}

func attributes(data []byte) (map[uint16][]byte, error) {
	out := map[uint16][]byte{}
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, fmt.Errorf("short conntrack attribute")
		}
		n := int(binary.NativeEndian.Uint16(data))
		if n < 4 || nlAlign4(n) > len(data) {
			return nil, fmt.Errorf("invalid conntrack attribute length %d", n)
		}
		out[binary.NativeEndian.Uint16(data[2:])&0x3fff] = data[4:n]
		data = data[nlAlign4(n):]
	}
	return out, nil
}
