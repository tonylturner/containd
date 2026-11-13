// SPDX-License-Identifier: Apache-2.0

package dpi

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestStreamViewPacketBoundaryAndRole(t *testing.T) {
	for _, offsets := range []bool{false, true} {
		t.Run(map[bool]string{false: "sequence", true: "offset"}[offsets], func(t *testing.T) {
			var view StreamView
			mgr := NewManager(&scriptedFramer{parse: func(v StreamView) (StreamResult, error) {
				view = v
				return StreamResult{NeedMore: true}, nil
			}})
			st := flow.NewState(flow.Key{Proto: 6}, time.Now())
			send := func(off int64, p string) {
				t.Helper()
				pkt := &ParsedPacket{Proto: "tcp", Payload: []byte(p), TCPSeqValid: !offsets, TCPSeq: uint32(100 + off),
					HasOffset: offsets, Session: "view", Dir: ClientToServer, Offset: off, Role: ServerToClient}
				r := mgr.Inspect(st, pkt)
				if r.Err != nil {
					t.Fatal(r.Err)
				}
				if view.Role != ServerToClient || view.Dir != ClientToServer {
					t.Fatalf("role changed identity: %+v", view)
				}
			}
			send(0, "ab")
			if !view.HasPacketStart || view.PacketStart != 0 {
				t.Fatal(view)
			}
			send(4, "ef") // out of order, not a recovery anchor
			if view.HasPacketStart {
				t.Fatal(view)
			}
			send(0, "ab") // duplicate
			if view.HasPacketStart {
				t.Fatal(view)
			}
			send(1, "bc") // partial retransmission adding a byte
			if view.HasPacketStart {
				t.Fatal(view)
			}
			send(3, "d") // fills the gap and absorbs old out-of-order bytes
			if !view.HasPacketStart || view.PacketStart != 3 || string(view.Bytes) != "abcdef" {
				t.Fatal(view)
			}
		})
	}
}

func TestStreamViewUnknownPacketOrder(t *testing.T) {
	var view StreamView
	mgr := NewManager(&scriptedFramer{parse: func(v StreamView) (StreamResult, error) {
		view = v
		return StreamResult{NeedMore: true}, nil
	}})
	st := flow.NewState(flow.Key{Proto: 6}, time.Now())
	mgr.Inspect(st, &ParsedPacket{Proto: "tcp", Payload: []byte("abc")})
	if view.HasPacketStart || view.Role != DirUnknown {
		t.Fatalf("invented transport facts: %+v", view)
	}
}

type resyncFramer struct {
	scriptedFramer
	resets int
}

func (f *resyncFramer) ResyncStream(_ *flow.State, _ StreamView, _ *StreamError) []Event {
	f.resets++
	return []Event{{Kind: "recovered"}}
}

func TestPassiveReassemblyResetPreservesPosition(t *testing.T) {
	for _, strict := range []bool{false, true} {
		f := &resyncFramer{}
		var view StreamView
		f.parse = func(v StreamView) (StreamResult, error) {
			view = v
			return StreamResult{NeedMore: true}, nil
		}
		mgr := smallManager(4, f)
		st := flow.NewState(flow.Key{Proto: 6}, time.Now())
		send := func(off int64, p string) InspectResult {
			return mgr.Inspect(st, &ParsedPacket{Proto: "tcp", Payload: []byte(p), HasOffset: true,
				Session: "bounded", Dir: ClientToServer, Offset: off, FailClosed: strict})
		}
		send(0, "ab")
		r := send(2, "cdef")
		if strict {
			if r.Err == nil || f.resets != 0 {
				t.Fatal("passive recovery bypassed fail-closed inspection", r)
			}
			continue
		}
		if r.Err != nil || f.resets != 1 || len(r.Events) != 1 {
			t.Fatal(r)
		}
		r = send(6, "gh")
		if r.Err != nil || view.Base != 6 || string(view.Bytes) != "gh" || !view.HasPacketStart || view.PacketStart != 0 {
			t.Fatalf("lost transport position after recovery: %+v %+v", r, view)
		}
	}
}
