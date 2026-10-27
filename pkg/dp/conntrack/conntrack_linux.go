// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package conntrack

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

// List reads both IP families and NAT tuples from the kernel over ctnetlink.
// It decodes records as they arrive and stops the dump once it holds limit
// entries; limit <= 0 reads the whole table. Permission errors, missing
// support, malformed records, cancellation and incomplete dumps are errors,
// not emptiness.
func List(ctx context.Context, limit int) ([]Entry, error) {
	sink := newEntrySink(limit)
	if err := exchange(ctx, 0x101, []byte{0, 0, 0, 0}, true, sink.add); err != nil {
		return nil, err
	}
	return sink.entries, nil
}

// entrySink keeps at most limit decoded entries (all when limit <= 0).
type entrySink struct {
	limit   int
	entries []Entry
}

func newEntrySink(limit int) *entrySink {
	return &entrySink{limit: limit, entries: []Entry{}}
}

// add decodes one ctnetlink record and reports whether the sink is full.
func (s *entrySink) add(record []byte) (bool, error) {
	e, err := parseEntry(record)
	if err != nil {
		return false, err
	}
	s.entries = append(s.entries, e)
	return s.limit > 0 && len(s.entries) >= s.limit, nil
}

func parseEntry(data []byte) (Entry, error) {
	e := Entry{}
	if len(data) < 4 {
		return e, fmt.Errorf("short conntrack record")
	}
	a, err := attributes(data[4:])
	if err != nil {
		return e, err
	}
	proto, tuple, err := parseTuple(a[1])
	if err != nil {
		return e, err
	}
	e.Proto = proto
	e.Src = tuple[0]
	e.Dst = tuple[1]
	e.Sport = tuple[2]
	e.Dport = tuple[3]
	replyProto, reply, err := parseTuple(a[2])
	if err != nil {
		return e, err
	}
	if proto != replyProto {
		return e, fmt.Errorf("conntrack tuple protocol mismatch")
	}
	e.ReplySrc = reply[0]
	e.ReplyDst = reply[1]
	e.ReplySport = reply[2]
	e.ReplyDport = reply[3]
	if v := a[7]; len(v) == 4 {
		e.TimeoutSecs = int(binary.BigEndian.Uint32(v))
	}
	if v := a[8]; len(v) == 4 {
		e.Mark = strconv.FormatUint(uint64(binary.BigEndian.Uint32(v)), 10)
	}
	if v := a[3]; len(v) == 4 {
		e.Assured = binary.BigEndian.Uint32(v)&4 != 0
	}
	if v := a[4]; len(v) > 0 {
		pi, err := attributes(v)
		if err != nil {
			return e, err
		}
		tcp, err := attributes(pi[1])
		if err != nil {
			return e, err
		}
		states := []string{"NONE", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE", "SYN_SENT2"}
		if state := tcp[1]; len(state) == 1 && int(state[0]) < len(states) {
			e.State = states[state[0]]
		}
	}
	return e, nil
}

func parseTuple(data []byte) (string, [4]string, error) {
	var t [4]string
	a, err := attributes(data)
	if err != nil {
		return "", t, err
	}
	ip, err := attributes(a[1])
	if err != nil {
		return "", t, err
	}
	p, err := attributes(a[2])
	if err != nil {
		return "", t, err
	}
	src, dst := ip[1], ip[2]
	if len(src) == 0 {
		src, dst = ip[3], ip[4]
	}
	if (len(src) != 4 && len(src) != 16) || len(src) != len(dst) || len(p[1]) != 1 {
		return "", t, fmt.Errorf("incomplete conntrack tuple")
	}
	t[0] = net.IP(src).String()
	t[1] = net.IP(dst).String()
	proto := strconv.Itoa(int(p[1][0]))
	switch p[1][0] {
	case 6:
		proto = "tcp"
	case 17:
		proto = "udp"
	case 1:
		proto = "icmp"
	case 58:
		proto = "icmpv6"
	}
	if proto == "tcp" || proto == "udp" {
		if len(p[2]) != 2 || len(p[3]) != 2 {
			return "", t, fmt.Errorf("incomplete conntrack ports")
		}
		t[2] = strconv.Itoa(int(binary.BigEndian.Uint16(p[2])))
		t[3] = strconv.Itoa(int(binary.BigEndian.Uint16(p[3])))
	}
	return proto, t, nil
}
