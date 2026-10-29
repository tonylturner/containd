// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package conntrack

import (
	"context"
	"encoding/binary"
	"errors"
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

var errUnexpectedSender = errors.New("ctnetlink unexpected sender")

// exchange sends one ctnetlink request and passes each reply record to record
// as it arrives. Records alias the receive buffer and are valid only during the
// call. exchange stops when record reports stop, the dump completes or the
// request is acknowledged; record may be nil for an acknowledged request. An
// interrupted dump is never presented as a verified empty table. exchange is
// the only owner of the socket and closes it on every return.
func exchange(ctx context.Context, typ uint16, payload []byte, dump bool, record func([]byte) (stop bool, err error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("ctnetlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("ctnetlink bind: %w", err)
	}
	s := querySocket{fd: fd, seq: uint32(time.Now().UnixNano()), buf: make([]byte, 1<<20)}
	return s.exchange(ctx, typ, payload, dump, record)
}

// querySocket has one owner. Exact lookups reuse its socket and bounded buffer;
// operator dumps retain their separate per-operation socket.
type querySocket struct {
	fd  int
	seq uint32
	buf []byte
}

func (s *querySocket) exchange(ctx context.Context, typ uint16, payload []byte, dump bool, record func([]byte) (bool, error)) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.seq++
	seq, fd := s.seq, s.fd
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
		return fmt.Errorf("ctnetlink send: %w", err)
	}
	buf := s.buf
	for {
		if err = ctx.Err(); err != nil {
			return fmt.Errorf("ctnetlink receive: %w", err)
		}
		ready := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		wait := 50
		if deadline, ok := ctx.Deadline(); ok {
			if remaining := int(time.Until(deadline).Milliseconds()); remaining < wait {
				wait = max(1, remaining)
			}
		}
		if _, err = unix.Poll(ready, wait); err == unix.EINTR {
			continue
		} else if err != nil {
			return err
		}
		n, _, recvFlags, from, err := unix.Recvmsg(fd, buf, nil, unix.MSG_DONTWAIT)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("ctnetlink receive: %w", err)
		}
		sender, ok := from.(*unix.SockaddrNetlink)
		if !ok {
			return errUnexpectedSender
		}
		records, done, err := parseDatagram(buf[:n], recvFlags, sender.Pid, seq, dump)
		if err != nil {
			return err
		}
		for _, r := range records {
			if record == nil {
				continue
			}
			stop, err := record(r)
			if err != nil || stop {
				return err
			}
		}
		if done {
			return nil
		}
	}
}

// parseDatagram validates one received netlink datagram and returns the
// payloads of its records for request seq, without copying them. done reports
// the end of a dump, or the acknowledgement of a non-dump request. Messages
// for other sequence numbers are ignored.
func parseDatagram(data []byte, recvFlags int, senderPid, seq uint32, dump bool) (records [][]byte, done bool, err error) {
	if recvFlags&unix.MSG_TRUNC != 0 {
		return nil, false, fmt.Errorf("ctnetlink truncated datagram")
	}
	if senderPid != 0 {
		return nil, false, errUnexpectedSender
	}
	msgs, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return nil, false, fmt.Errorf("ctnetlink messages: %w", err)
	}
	// ParseNetlinkMessage silently drops a trailing fragment shorter than a header.
	consumed := 0
	for _, m := range msgs {
		consumed += nlAlign4(int(m.Header.Len))
	}
	if consumed != len(data) {
		return nil, false, fmt.Errorf("ctnetlink messages: %d trailing bytes", len(data)-consumed)
	}
	for _, m := range msgs {
		if m.Header.Seq != seq {
			continue
		}
		if m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
			return nil, false, fmt.Errorf("conntrack dump interrupted")
		}
		switch m.Header.Type {
		case unix.NLMSG_DONE:
			if len(m.Data) >= 4 && int32(binary.NativeEndian.Uint32(m.Data)) != 0 {
				return nil, false, fmt.Errorf("ctnetlink dump: %w", unix.Errno(-int32(binary.NativeEndian.Uint32(m.Data))))
			}
			return records, true, nil
		case unix.NLMSG_ERROR:
			if len(m.Data) < 4 {
				return nil, false, fmt.Errorf("ctnetlink short acknowledgement")
			}
			code := int32(binary.NativeEndian.Uint32(m.Data))
			if code != 0 {
				return nil, false, fmt.Errorf("ctnetlink: %w", unix.Errno(-code))
			}
			if !dump {
				return records, true, nil
			}
		default:
			records = append(records, m.Data)
		}
	}
	return records, false, nil
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
