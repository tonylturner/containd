// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package conntrack

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	testSeq    = uint32(7)
	ctNewMsg   = uint16(0x100)
	multiFlags = uint16(unix.NLM_F_MULTI)
)

func nlMsg(typ, flags uint16, seq uint32, data []byte) []byte {
	b := make([]byte, nlAlign4(16+len(data)))
	binary.NativeEndian.PutUint32(b, uint32(16+len(data)))
	binary.NativeEndian.PutUint16(b[4:], typ)
	binary.NativeEndian.PutUint16(b[6:], flags)
	binary.NativeEndian.PutUint32(b[8:], seq)
	copy(b[16:], data)
	return b
}

// errnoMsg carries a negative errno, as the kernel reports failures.
func errnoMsg(typ uint16, seq uint32, errno unix.Errno) []byte {
	data := make([]byte, 20)
	binary.NativeEndian.PutUint32(data, uint32(-int32(errno)))
	return nlMsg(typ, 0, seq, data)
}

func ctRecord(src, dst string, sport uint16) []byte {
	data := append([]byte{0, 0, 0, 0}, nlAttr(1|0x8000, fixtureTuple(src, dst, sport, 443))...)
	return append(data, nlAttr(2|0x8000, fixtureTuple(dst, src, 443, sport))...)
}

func ctMsg(seq uint32, src string, sport uint16) []byte {
	dst := "198.51.100.1"
	if strings.Contains(src, ":") {
		dst = "2001:db8::ff"
	}
	return nlMsg(ctNewMsg, multiFlags, seq, ctRecord(src, dst, sport))
}

func datagram(msgs ...[]byte) []byte {
	var b []byte
	for _, m := range msgs {
		b = append(b, m...)
	}
	return b
}

func TestDatagramMultipartAcrossTwo(t *testing.T) {
	sink := newEntrySink(0)
	first, done, err := parseDatagram(datagram(ctMsg(testSeq, "192.0.2.1", 1001), ctMsg(testSeq, "2001:db8::1", 1002)), 0, 0, testSeq, true)
	if err != nil || done || len(first) != 2 {
		t.Fatalf("first datagram: %d records done=%v err=%v", len(first), done, err)
	}
	for _, r := range first {
		if full, err := sink.add(r); err != nil || full {
			t.Fatalf("add: full=%v err=%v", full, err)
		}
	}
	second, done, err := parseDatagram(datagram(ctMsg(testSeq, "192.0.2.3", 1003), nlMsg(unix.NLMSG_DONE, multiFlags, testSeq, []byte{0, 0, 0, 0})), 0, 0, testSeq, true)
	if err != nil || !done || len(second) != 1 {
		t.Fatalf("second datagram: %d records done=%v err=%v", len(second), done, err)
	}
	if _, err := sink.add(second[0]); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range sink.entries {
		got = append(got, e.Src+":"+e.Sport)
	}
	if strings.Join(got, ",") != "192.0.2.1:1001,2001:db8::1:1002,192.0.2.3:1003" {
		t.Fatalf("entries: %v", got)
	}
}

func TestDatagramIgnoresForeignSequence(t *testing.T) {
	foreign := testSeq + 1
	records, done, err := parseDatagram(datagram(
		ctMsg(foreign, "192.0.2.9", 9),
		nlMsg(ctNewMsg, multiFlags|unix.NLM_F_DUMP_INTR, foreign, ctRecord("192.0.2.9", "198.51.100.1", 9)),
		errnoMsg(unix.NLMSG_ERROR, foreign, unix.EPERM),
		ctMsg(testSeq, "192.0.2.1", 1001),
		nlMsg(unix.NLMSG_DONE, multiFlags, foreign, []byte{0, 0, 0, 0}),
	), 0, 0, testSeq, true)
	if err != nil || done || len(records) != 1 {
		t.Fatalf("%d records done=%v err=%v", len(records), done, err)
	}
	if e, err := parseEntry(records[0]); err != nil || e.Src != "192.0.2.1" {
		t.Fatalf("record: %+v %v", e, err)
	}
}

func TestDatagramErrors(t *testing.T) {
	valid := ctMsg(testSeq, "192.0.2.1", 1001)
	for _, tc := range []struct {
		name      string
		data      []byte
		recvFlags int
		pid       uint32
		dump      bool
		want      string
		errno     unix.Errno
	}{
		{name: "dump interrupted", data: datagram(valid, nlMsg(ctNewMsg, multiFlags|unix.NLM_F_DUMP_INTR, testSeq, ctRecord("192.0.2.2", "198.51.100.1", 2))), dump: true, want: "interrupted"},
		{name: "permission denied", data: errnoMsg(unix.NLMSG_ERROR, testSeq, unix.EPERM), dump: true, want: "ctnetlink", errno: unix.EPERM},
		{name: "unsupported", data: errnoMsg(unix.NLMSG_ERROR, testSeq, unix.EOPNOTSUPP), dump: true, want: "ctnetlink", errno: unix.EOPNOTSUPP},
		{name: "ack error", data: errnoMsg(unix.NLMSG_ERROR, testSeq, unix.ENOENT), want: "ctnetlink", errno: unix.ENOENT},
		{name: "short ack", data: nlMsg(unix.NLMSG_ERROR, 0, testSeq, []byte{0, 0}), dump: true, want: "short acknowledgement"},
		{name: "done with error", data: datagram(valid, errnoMsg(unix.NLMSG_DONE, testSeq, unix.ENOBUFS)), dump: true, want: "ctnetlink dump", errno: unix.ENOBUFS},
		{name: "truncated", data: valid, recvFlags: unix.MSG_TRUNC, dump: true, want: "truncated"},
		{name: "non-kernel sender", data: valid, pid: 4242, dump: true, want: "unexpected sender"},
		{name: "short header", data: valid[:10], dump: true, want: "ctnetlink messages"},
		{name: "length beyond datagram", data: valid[:len(valid)-8], dump: true, want: "ctnetlink messages"},
		{name: "trailing fragment", data: datagram(valid, []byte{1, 2, 3, 4}), dump: true, want: "trailing bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records, done, err := parseDatagram(tc.data, tc.recvFlags, tc.pid, testSeq, tc.dump)
			if err == nil || !strings.Contains(err.Error(), tc.want) || records != nil || done {
				t.Fatalf("records=%d done=%v err=%v, want error containing %q", len(records), done, err, tc.want)
			}
			if tc.errno != 0 && !errors.Is(err, tc.errno) {
				t.Fatalf("err %v does not wrap %v", err, tc.errno)
			}
		})
	}
}

func TestDatagramAcknowledgement(t *testing.T) {
	ack := errnoMsg(unix.NLMSG_ERROR, testSeq, 0)
	if records, done, err := parseDatagram(ack, 0, 0, testSeq, false); err != nil || !done || len(records) != 0 {
		t.Fatalf("request ack: %d records done=%v err=%v", len(records), done, err)
	}
	if _, done, err := parseDatagram(ack, 0, 0, testSeq, true); err != nil || done {
		t.Fatalf("dump ack: done=%v err=%v", done, err)
	}
}

func TestEmptyDumpIsEmptyTable(t *testing.T) {
	sink := newEntrySink(10)
	records, done, err := parseDatagram(nlMsg(unix.NLMSG_DONE, multiFlags, testSeq, []byte{0, 0, 0, 0}), 0, 0, testSeq, true)
	if err != nil || !done || len(records) != 0 {
		t.Fatalf("%d records done=%v err=%v", len(records), done, err)
	}
	if sink.entries == nil || len(sink.entries) != 0 {
		t.Fatalf("entries: %#v", sink.entries)
	}
}

func TestEntrySinkLimit(t *testing.T) {
	sink := newEntrySink(2)
	for i, want := range []bool{false, true} {
		full, err := sink.add(ctRecord("192.0.2.1", "198.51.100.1", uint16(1000+i)))
		if err != nil || full != want {
			t.Fatalf("add %d: full=%v err=%v", i, full, err)
		}
	}
	if len(sink.entries) != 2 {
		t.Fatalf("entries: %d", len(sink.entries))
	}
	all := newEntrySink(0)
	for i := 0; i < 3; i++ {
		if full, err := all.add(ctRecord("192.0.2.1", "198.51.100.1", uint16(1000+i))); err != nil || full {
			t.Fatalf("unlimited add %d: full=%v err=%v", i, full, err)
		}
	}
}

func TestEntrySinkMalformedRecord(t *testing.T) {
	good := ctRecord("192.0.2.1", "198.51.100.1", 1001)
	// The original tuple claims more bytes than its parent attribute holds.
	overlong := append([]byte(nil), good...)
	binary.NativeEndian.PutUint16(overlong[4:], uint16(len(good)))
	// A nested address attribute shorter than an attribute header.
	short := append([]byte{0, 0, 0, 0}, nlAttr(1|0x8000, nlAttr(1|0x8000, []byte{2, 0}))...)
	for name, record := range map[string][]byte{"overlong": overlong, "short nested": short, "short record": {0, 0}} {
		sink := newEntrySink(5)
		if _, err := sink.add(good); err != nil {
			t.Fatal(err)
		}
		if full, err := sink.add(record); err == nil || full {
			t.Fatalf("%s: full=%v err=%v", name, full, err)
		}
	}
}

func TestListCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	entries, err := List(ctx, 10)
	if !errors.Is(err, context.Canceled) || entries != nil {
		t.Fatalf("canceled list: %v %v", entries, err)
	}
}
