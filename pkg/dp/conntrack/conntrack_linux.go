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
	orig, err := parseTuple(a[1])
	if err != nil {
		return e, err
	}
	reply, err := parseTuple(a[2])
	if err != nil {
		return e, err
	}
	if orig.proto != reply.proto {
		return e, fmt.Errorf("conntrack tuple protocol mismatch")
	}
	e.Proto = orig.proto
	e.Src, e.Dst, e.Sport, e.Dport = orig.src, orig.dst, orig.sport, orig.dport
	e.ICMPID, e.ICMPType, e.ICMPCode = orig.icmpID, orig.icmpType, orig.icmpCode
	e.ReplySrc, e.ReplyDst, e.ReplySport, e.ReplyDport = reply.src, reply.dst, reply.sport, reply.dport
	e.ReplyICMPID, e.ReplyICMPType, e.ReplyICMPCode = reply.icmpID, reply.icmpType, reply.icmpCode
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

// tuple is one direction of a conntrack entry. TCP and UDP set the ports;
// ICMP and ICMPv6 set the identifier, type and code.
type tuple struct {
	proto, src, dst, sport, dport, icmpID, icmpType, icmpCode string
}

// CTA_PROTO_* attributes of a tuple's protocol nest
// (linux/netfilter/nfnetlink_conntrack.h).
const (
	ctaProtoNum        = 1
	ctaProtoSrcPort    = 2
	ctaProtoDstPort    = 3
	ctaProtoICMPID     = 4
	ctaProtoICMPType   = 5
	ctaProtoICMPCode   = 6
	ctaProtoICMPv6ID   = 7
	ctaProtoICMPv6Type = 8
	ctaProtoICMPv6Code = 9
)

// icmpAttrs are the identifier, type and code attributes of each ICMP protocol number.
var icmpAttrs = map[byte][3]uint16{
	1:  {ctaProtoICMPID, ctaProtoICMPType, ctaProtoICMPCode},
	58: {ctaProtoICMPv6ID, ctaProtoICMPv6Type, ctaProtoICMPv6Code},
}

func parseTuple(data []byte) (tuple, error) {
	var t tuple
	a, err := attributes(data)
	if err != nil {
		return t, err
	}
	ip, err := attributes(a[1])
	if err != nil {
		return t, err
	}
	p, err := attributes(a[2])
	if err != nil {
		return t, err
	}
	src, dst := ip[1], ip[2]
	if len(src) == 0 {
		src, dst = ip[3], ip[4]
	}
	if (len(src) != 4 && len(src) != 16) || len(src) != len(dst) || len(p[ctaProtoNum]) != 1 {
		return t, fmt.Errorf("incomplete conntrack tuple")
	}
	t.src = net.IP(src).String()
	t.dst = net.IP(dst).String()
	num := p[ctaProtoNum][0]
	t.proto = strconv.Itoa(int(num))
	switch num {
	case 6:
		t.proto = "tcp"
	case 17:
		t.proto = "udp"
	case 1:
		t.proto = "icmp"
	case 58:
		t.proto = "icmpv6"
	}
	if t.proto == "tcp" || t.proto == "udp" {
		if len(p[ctaProtoSrcPort]) != 2 || len(p[ctaProtoDstPort]) != 2 {
			return t, fmt.Errorf("incomplete conntrack ports")
		}
		t.sport = strconv.Itoa(int(binary.BigEndian.Uint16(p[ctaProtoSrcPort])))
		t.dport = strconv.Itoa(int(binary.BigEndian.Uint16(p[ctaProtoDstPort])))
	}
	if attrs, ok := icmpAttrs[num]; ok {
		id, typ, code := p[attrs[0]], p[attrs[1]], p[attrs[2]]
		if len(id) != 2 || len(typ) != 1 || len(code) != 1 {
			return t, fmt.Errorf("incomplete conntrack %s tuple", t.proto)
		}
		t.icmpID = strconv.Itoa(int(binary.BigEndian.Uint16(id)))
		t.icmpType = strconv.Itoa(int(typ[0]))
		t.icmpCode = strconv.Itoa(int(code[0]))
	}
	return t, nil
}
