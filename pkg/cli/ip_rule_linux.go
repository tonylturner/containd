// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Minimal fib_rule support (IPv4) for "show ip rule" without requiring iproute2 in the image.
// We only decode selectors and table/priority.
type fibRuleHdr struct {
	Family  uint8
	DstLen  uint8
	SrcLen  uint8
	Tos     uint8
	Table   uint8
Res1   uint8
Res2   uint8
Action  uint8
Flags   uint32
}

const (
	fraDst      = 1
	fraSrc      = 2
	fraIifname  = 3
	fraOifname  = 4
	fraPriority = 6
	fraTable    = 15
)

type ipRule struct {
	priority uint32
	table    uint32
	src      string
	dst      string
	iif      string
	oif      string
}

func showIPRule() Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		rules, err := listIPv4Rules(ctx)
		if err != nil {
			return err
		}
		t := newTable("PRIORITY", "SRC", "DST", "TABLE", "IIF", "OIF")
		for _, r := range rules {
			src := r.src
			if src == "" {
				src = "—"
			}
			dst := r.dst
			if dst == "" {
				dst = "—"
			}
			iif := r.iif
			if iif == "" {
				iif = "—"
			}
			oif := r.oif
			if oif == "" {
				oif = "—"
			}
			t.addRow(fmt.Sprintf("%d", r.priority), src, dst, fmt.Sprintf("%d", r.table), iif, oif)
		}
		t.render(out)
		return nil
	}
}

func listIPv4Rules(ctx context.Context) ([]ipRule, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}

	seq := uint32(time.Now().UnixNano() & 0xffffffff)
	var req bytes.Buffer
	hdr := unix.NlMsghdr{
		Type:  unix.RTM_GETRULE,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_DUMP,
		Seq:   seq,
		Pid:   uint32(os.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	fr := fibRuleHdr{Family: unix.AF_INET}
	_ = binary.Write(&req, binary.LittleEndian, fr)
	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}

	var rules []ipRule
	buf := make([]byte, 1<<16)
	hdrSize := int(unsafe.Sizeof(fibRuleHdr{}))
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue
			}
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				sort.Slice(rules, func(i, j int) bool {
					if rules[i].priority != rules[j].priority {
						return rules[i].priority < rules[j].priority
					}
					if rules[i].table != rules[j].table {
						return rules[i].table < rules[j].table
					}
					if rules[i].src != rules[j].src {
						return rules[i].src < rules[j].src
					}
					return rules[i].dst < rules[j].dst
				})
				return rules, nil
			case unix.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return nil, errors.New("netlink error")
				}
				code := int32(binary.LittleEndian.Uint32(m.Data[:4]))
				if code == 0 {
					continue
				}
				return nil, unix.Errno(-code)
			case unix.RTM_NEWRULE:
				if len(m.Data) < hdrSize {
					continue
				}
				fr := (*fibRuleHdr)(unsafe.Pointer(&m.Data[0]))
				if fr.Family != unix.AF_INET {
					continue
				}
				r := ipRule{table: uint32(fr.Table)}
				for _, a := range parseNetlinkAttrs(m.Data[hdrSize:]) {
					switch a.Type {
					case fraPriority:
						if len(a.Value) >= 4 {
							r.priority = binary.LittleEndian.Uint32(a.Value[:4])
						}
					case fraTable:
						if len(a.Value) >= 4 {
							r.table = binary.LittleEndian.Uint32(a.Value[:4])
						}
					case fraSrc:
						if ip := net.IP(append([]byte(nil), a.Value...)).To4(); ip != nil {
							r.src = fmt.Sprintf("%s/%d", ip.String(), fr.SrcLen)
						}
					case fraDst:
						if ip := net.IP(append([]byte(nil), a.Value...)).To4(); ip != nil {
							r.dst = fmt.Sprintf("%s/%d", ip.String(), fr.DstLen)
						}
					case fraIifname:
						r.iif = string(bytes.TrimRight(a.Value, "\x00"))
					case fraOifname:
						r.oif = string(bytes.TrimRight(a.Value, "\x00"))
					}
				}
				rules = append(rules, r)
			}
		}
	}
}

type netlinkAttr struct {
	Type  uint16
	Value []byte
}

func parseNetlinkAttrs(b []byte) []netlinkAttr {
	out := []netlinkAttr{}
	for len(b) >= 4 {
		l := int(binary.LittleEndian.Uint16(b[0:2]))
		t := binary.LittleEndian.Uint16(b[2:4])
		if l < 4 || l > len(b) {
			break
		}
		v := b[4:l]
		out = append(out, netlinkAttr{Type: t, Value: append([]byte(nil), v...)})
		// Align to 4 bytes.
		adv := (l + 3) & ^3
		if adv > len(b) {
			break
		}
		b = b[adv:]
	}
	return out
}

