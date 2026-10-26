// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// managementRequest uses a private socket per transaction, bounded by context
// and a two-second ceiling. No replies can be consumed by the subscription.
func managementRequest(ctx context.Context, kind uint16, flags uint16, payload []byte) ([]syscall.NetlinkMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	seq := atomic.AddUint32(&nlSeq, 1)
	var b bytes.Buffer
	hdr := unix.NlMsghdr{Len: uint32(unix.NLMSG_HDRLEN + len(payload)), Type: kind, Flags: unix.NLM_F_REQUEST | flags, Seq: seq}
	_ = binary.Write(&b, binary.NativeEndian, hdr)
	b.Write(payload)
	if err := unix.Sendto(fd, b.Bytes(), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	var out []syscall.NetlinkMessage
	buf := make([]byte, 1<<20)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		polls := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(polls, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			continue
		}
		n, _, recvflags, _, err := unix.Recvmsg(fd, buf, nil, 0)
		if err != nil {
			return nil, err
		}
		if recvflags&unix.MSG_TRUNC != 0 {
			return nil, fmt.Errorf("management netlink response truncated")
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue
			}
			if m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				return nil, fmt.Errorf("management netlink dump interrupted")
			}
			if m.Header.Type == unix.NLMSG_DONE {
				return out, nil
			}
			if m.Header.Type == unix.NLMSG_ERROR {
				if err := netlinkMessageError(m.Data); err != nil {
					return nil, err
				}
				// GET dump bits overlap NEW REPLACE/EXCL bits. A partial
				// match is not a dump; mutations complete on their ACK.
				if flags&unix.NLM_F_DUMP != unix.NLM_F_DUMP {
					return out, nil
				}
				continue
			}
			out = append(out, m)
		}
	}
}
func managementPayload(v any) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.NativeEndian, v)
	return b.Bytes()
}
func managementAttrU32(b *bytes.Buffer, kind uint16, value uint32) {
	data := make([]byte, 4)
	binary.NativeEndian.PutUint32(data, value)
	addRtAttr(b, kind, data)
}

func managementDump(ctx context.Context, kind uint16) ([]syscall.NetlinkMessage, error) {
	var payload []byte
	switch kind {
	case unix.RTM_GETADDR:
		payload = managementPayload(unix.IfAddrmsg{Family: unix.AF_INET})
	case unix.RTM_GETROUTE:
		payload = managementPayload(unix.RtMsg{Family: unix.AF_INET})
	case unix.RTM_GETRULE:
		payload = managementPayload(fibRuleHdr{Family: unix.AF_INET})
	}
	return managementRequest(ctx, kind, unix.NLM_F_DUMP, payload)
}

type managementRoute struct {
	header   unix.RtMsg
	table    uint32
	dst, src []byte
	index    uint32
	payload  []byte
}

func parseManagementRoute(m syscall.NetlinkMessage) (managementRoute, bool) {
	if m.Header.Type != unix.RTM_NEWROUTE || len(m.Data) < unix.SizeofRtMsg {
		return managementRoute{}, false
	}
	h := *(*unix.RtMsg)(unsafe.Pointer(&m.Data[0]))
	if h.Family != unix.AF_INET {
		return managementRoute{}, false
	}
	r := managementRoute{header: h, table: uint32(h.Table), payload: m.Data}
	for _, a := range parseNetlinkAttrs(m.Data[unix.SizeofRtMsg:]) {
		switch a.Type {
		case unix.RTA_DST:
			r.dst = a.Value
		case unix.RTA_PREFSRC:
			r.src = a.Value
		case unix.RTA_OIF:
			if len(a.Value) == 4 {
				r.index = binary.NativeEndian.Uint32(a.Value)
			}
		case unix.RTA_TABLE:
			if len(a.Value) == 4 {
				r.table = binary.NativeEndian.Uint32(a.Value)
			}
		}
	}
	return r, true
}
