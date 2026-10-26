// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package dpi

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func feedVerify(r *reassembler, key string, seq uint32, verify bool, data ...byte) feedResult {
	return r.feed(key, position{kind: posSeq, seq: seq}, data, testNow, true, false, verify)
}

// A verifying stream compares retransmitted consumed bytes with its
// history; other streams take them as duplicates unseen.
func TestReassemblerVerifiesConsumedBytes(t *testing.T) {
	for _, verify := range []bool{false, true} {
		r := newReassembler(64, time.Minute)
		r.open("f", 100, testNow, verify)
		wantBuf(t, feedVerify(r, "f", 100, verify, 1, 2, 3, 4), 0, 1, 2, 3, 4)
		r.trim("f", 0, 4)
		wantBuf(t, feedVerify(r, "f", 104, verify, 5, 6), 4, 5, 6)
		// Identical consumed and held bytes are duplicates either way.
		wantBuf(t, feedVerify(r, "f", 102, verify, 3, 4, 5), 4, 5, 6)
		if got := r.retransmissions("f"); got != 1 {
			t.Fatalf("verify=%v: retransmissions = %d, want 1", verify, got)
		}
		rewritten := feedVerify(r, "f", 101, verify, 2, 9, 4, 5, 6, 7)
		if !verify {
			wantBuf(t, rewritten, 4, 5, 6, 7)
			continue
		}
		wantStreamErr(t, rewritten, StreamOverlapConflict, 2)
		if _, held := r.stats(); held != storedTotal(r) || held != 6 {
			t.Fatalf("bytes held %d (recomputed %d), want 4 consumed + 2 held", held, storedTotal(r))
		}
	}
}

// The history keeps the last maxSize consumed bytes; an older consumed byte
// cannot be verified. Turning verification off drops the history.
func TestReassemblerHistoryBound(t *testing.T) {
	r := newReassembler(4, time.Minute)
	r.open("f", 100, testNow, true)
	for i := range uint32(3) {
		b := byte(3 * i)
		wantBuf(t, feedVerify(r, "f", 100+3*i, true, b, b+1, b+2), int64(3*i), b, b+1, b+2)
		r.trim("f", int64(3*i), 3)
	}
	// Consumed [0,9); the history holds [5,9).
	wantBuf(t, feedVerify(r, "f", 105, true, 5, 6, 7, 8), 9)
	wantStreamErr(t, feedVerify(r, "f", 104, true, 4, 5), StreamUnverifiedRetransmission, 4)
	if _, held := r.stats(); held != 4 {
		t.Fatalf("bytes held = %d, want the 4-byte history", held)
	}
	wantBuf(t, feedVerify(r, "f", 109, false, 9), 9, 9)
	if _, held := r.stats(); held != 1 || storedTotal(r) != 1 {
		t.Fatalf("bytes held = %d, want the history dropped", held)
	}
	r.complete("f")
	if streams, held := r.stats(); streams != 0 || held != 0 {
		t.Fatalf("after complete: %d streams, %d bytes", streams, held)
	}
}

func failClosedSeg(seq uint32, payload ...byte) *ParsedPacket {
	p := tcpSeg(seq, payload...)
	p.FailClosed = true
	return p
}

// A fail-closed stream that errs stays failed: later packets return the
// error without parsing, the idle sweep keeps it, and only the flow's end
// (or a packet that no longer fails closed) starts a new stream.
func TestInspectFailClosedStreamStaysFailed(t *testing.T) {
	for _, tc := range []struct {
		name string
		bad  *ParsedPacket
		kind StreamErrKind // 0: a FrameError
	}{
		{"rewritten consumed bytes", failClosedSeg(0, 0x01, 0xBB), StreamOverlapConflict},
		{"unframeable bytes", failClosedSeg(2, 0xFF), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr, _, st := framedFixture()
			mgr.Inspect(st, synSeg(0, true))
			if res := mgr.Inspect(st, failClosedSeg(0, 0x01, 0xAA)); res.Err != nil || !reflect.DeepEqual(ranges(res), []frameRange{{0, 2}}) {
				t.Fatalf("first frame Err=%v frames=%v", res.Err, ranges(res))
			}
			res := mgr.Inspect(st, tc.bad)
			var se *StreamError
			var fe *FrameError
			if tc.kind != 0 && (!errors.As(res.Err, &se) || se.Kind != tc.kind) || tc.kind == 0 && !errors.As(res.Err, &fe) {
				t.Fatalf("Err = %v, want kind %v", res.Err, tc.kind)
			}
			if n := len(res.Events); n == 0 || res.Events[n-1].Kind != "malformed" {
				t.Fatalf("events = %v, want the malformed event last", res.Events)
			}
			mgr.reassembler.sweep(time.Now().Add(time.Hour))
			again := mgr.Inspect(st, failClosedSeg(3, 0x00))
			if again.Err != res.Err || len(again.Frames) != 0 || len(again.Events) != 0 || !again.Framed {
				t.Fatalf("after the failure Err=%v frames=%v events=%v, want the same error and nothing parsed", again.Err, ranges(again), again.Events)
			}
			if _, held := mgr.reassembler.stats(); held != 0 {
				t.Fatalf("failed stream holds %d bytes", held)
			}
			if _, err := mgr.OnFlowEnd(st); err != nil {
				t.Fatal(err)
			}
			mgr.Inspect(st, synSeg(10, true))
			fresh := mgr.Inspect(st, failClosedSeg(10, 0x00))
			if fresh.Err != nil || !reflect.DeepEqual(ranges(fresh), []frameRange{{0, 1}}) {
				t.Fatalf("after flow end Err=%v frames=%v", fresh.Err, ranges(fresh))
			}
		})
	}
}

// A failed stream of a flow that no longer fails closed restarts at the
// next packet, as a legacy stream does.
func TestInspectFailedStreamRestartsWithoutFailClosed(t *testing.T) {
	mgr, _, st := framedFixture()
	mgr.Inspect(st, synSeg(0, true))
	mgr.Inspect(st, failClosedSeg(0, 0xFF))
	if res := mgr.Inspect(st, failClosedSeg(1, 0x00)); res.Err == nil {
		t.Fatal("fail-closed stream did not stay failed")
	}
	fresh := mgr.Inspect(st, tcpSeg(5, 0x00))
	if fresh.Err != nil || !reflect.DeepEqual(ranges(fresh), []frameRange{{0, 1}}) {
		t.Fatalf("Err=%v frames=%v, want a fresh stream", fresh.Err, ranges(fresh))
	}
}

// Without FailClosed a rewritten retransmission of consumed bytes is a
// duplicate and a framing error restarts the stream, as before.
func TestInspectLegacyStreamUnchanged(t *testing.T) {
	mgr, _, st := framedFixture()
	mgr.Inspect(st, tcpSeg(0, 0x01, 0xAA))
	if res := mgr.Inspect(st, tcpSeg(0, 0x01, 0xBB)); res.Err != nil || len(res.Frames) != 0 {
		t.Fatalf("rewritten consumed bytes Err=%v frames=%v, want an unseen duplicate", res.Err, ranges(res))
	}
	if res := mgr.Inspect(st, tcpSeg(2, 0xFF)); res.Err == nil {
		t.Fatal("unframeable bytes did not fail")
	}
	fresh := mgr.Inspect(st, tcpSeg(3, 0x00))
	if fresh.Err != nil || !reflect.DeepEqual(ranges(fresh), []frameRange{{0, 1}}) {
		t.Fatalf("Err=%v frames=%v, want the stream restarted", fresh.Err, ranges(fresh))
	}
}
