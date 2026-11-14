// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"encoding/binary"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/inventory"
)

func inventoryAttempts(t *testing.T, h *iecHarness, attempted uint64) {
	t.Helper()
	s := h.e.Inventory().SnapshotIEC104()
	if len(s.Pairs) != 1 || s.Pairs[0].AttemptedCommands != attempted {
		t.Fatalf("want %d attempted commands: %+v", attempted, s)
	}
}

func TestIECInventoryAttemptsAndEvidence(t *testing.T) {
	for _, fate := range []string{"allow", "deny", "monitor", "not-inline", "would-drop"} {
		t.Run(fate, func(t *testing.T) {
			mode := "enforce"
			if fate == "monitor" || fate == "would-drop" {
				mode = "monitor"
			}
			h := newAPCIHarness(t, mode)
			if fate == "deny" || fate == "would-drop" {
				h.e.sessions.policy = h.policy
				h.policy.allowType = 100 // deny command Type46
			}
			var mu sync.Mutex
			var outcomes []dpi.Event
			parents := 0
			h.e.SetLearnWatchHook(func(state *flow.State, events []dpi.Event) {
				mu.Lock()
				defer mu.Unlock()
				if state != nil {
					parents += len(events)
				} else {
					outcomes = append(outcomes, events...)
				}
			})
			t.Cleanup(func() { h.e.SetLearnWatchHook(nil) })
			h.handshake()
			p := h.pkt(true, capture.TCPFlagACK, h.cSeq, h.sSeq, apdu(46, 6, 7, 101, 2))
			if fate == "not-inline" {
				p.Token = capture.Token{}
			}
			d := h.e.handlePacket(p)
			want := capture.Repeat
			if fate == "deny" {
				want = capture.Drop
			} else if fate == "not-inline" {
				want = capture.Accept
			}
			if d.Action != want {
				t.Fatalf("decision=%+v, want %v", d, want)
			}
			if d.Action == capture.Drop {
				h.e.hooks.onVerdict(p.Token, capture.VerdictDrop, nil)
			}
			inventoryAttempts(t, h, 1)
			mu.Lock()
			defer mu.Unlock()
			if parents == 0 {
				t.Fatal("no decoded evidence reached the watch")
			}
			decisionID, blockedID := "", ""
			for _, event := range outcomes {
				if event.Kind == "evidence.delivery" || event.Attributes["delivery"] == "delivered" {
					t.Fatalf("kernel continuation claimed delivery: %+v", event)
				}
				if event.Kind == "ics.decision" {
					if fate == "deny" && event.Attributes["decision"] != "deny" || fate == "would-drop" && event.Attributes["decision"] != "would_drop" {
						t.Fatalf("decision evidence changed: %+v", event)
					}
					decisionID, _ = event.Attributes["apdu_id"].(string)
				}
				if event.Kind == "ics.verdict" && event.Attributes["outcome"] == "dropped" {
					blockedID, _ = event.Attributes["trigger_apdu_id"].(string)
					ids, ok := event.Attributes["apdu_ids"].([]string)
					if !ok || len(ids) != 1 || ids[0] != blockedID {
						t.Fatalf("blocked carrying evidence changed: %+v", event)
					}
				}
			}
			if (fate == "deny" || fate == "would-drop") && decisionID == "" {
				t.Fatal("missing decision evidence")
			}
			if fate == "deny" && blockedID != decisionID {
				t.Fatal("blocked outcome lost its decision APDU identity")
			}
		})
	}
}

func TestIECInventorySplitCoalescedOutOfOrderAndRetransmit(t *testing.T) {
	h := newAPCIHarness(t, "enforce")
	h.handshake()
	cmd := apdu(46, 6, 1, 101, 2)
	second := append([]byte(nil), cmd...)
	second[12] = 102 // distinct command; TCP duplicates below remain identical
	payload := append(append(append([]byte{}, cmd...), second...), 0x68)
	seq := h.cSeq
	for _, r := range [][2]int{{9, len(payload)}, {9, len(payload)}, {0, 9}} {
		p := h.pkt(true, capture.TCPFlagACK, seq+uint32(r[0]), h.sSeq, payload[r[0]:r[1]])
		d := h.e.handlePacket(p)
		if r[0] == 9 && d.Action != capture.Hold || r[0] == 0 && d.Action != capture.Repeat {
			t.Fatalf("unexpected split disposition: %+v", d)
		}
	}
	inventoryAttempts(t, h, 2)
	p := h.pkt(true, capture.TCPFlagACK, seq, h.sSeq, payload[:9])
	h.e.handlePacket(p)
	// Completing the partial U-frame releases the real held carrying tokens.
	release := h.e.handlePacket(h.pkt(true, capture.TCPFlagACK, seq+uint32(len(payload)), h.sSeq, startdtAct[1:]))
	if release.Action != capture.Repeat || len(release.Resolved) != 2 {
		t.Fatalf("held tails were not released: %+v", release)
	}
	for _, resolution := range release.Resolved {
		h.e.hooks.onVerdict(resolution.Token, resolution.Verdict, nil)
	}
	h.e.handlePacket(h.pkt(true, capture.TCPFlagACK, seq, h.sSeq, payload[:len(payload)-1]))
	inventoryAttempts(t, h, 2)
	if state, _ := h.sessionState(); state != sessionEstablished {
		t.Fatal("successful Repeat lost the live session")
	}
}

func TestIECInventoryAbortWhileCommandHeld(t *testing.T) {
	h := newAPCIHarness(t, "enforce")
	h.handshake()
	p, d := h.send(true, append(apdu(46, 6, 1, 101, 2), 0x68))
	if d.Action != capture.Hold {
		t.Fatal(d)
	}
	inventoryAttempts(t, h, 1)
	h.e.sessions.onSourceDown()
	h.e.hooks.onVerdict(p.Token, capture.VerdictDrop, capture.ErrQueueClosed)
	inventoryAttempts(t, h, 1)
	if state, _ := h.sessionState(); state != sessionAborted {
		t.Fatal("queue loss did not retire command authority")
	}
}

func TestIECInventoryDroppedRetransmission(t *testing.T) {
	h := newAPCIHarness(t, "enforce")
	h.handshake()
	p, _ := h.send(true, apdu(46, 6, 1, 101, 2))
	h.send(false, nil) // ACK releases the original byte history.
	p.Token = h.token()
	if d := h.e.handlePacket(p); d.Action != capture.Drop {
		t.Fatalf("expected below-floor drop: %+v", d)
	}
	h.e.hooks.onVerdict(p.Token, capture.VerdictDrop, nil)
	inventoryAttempts(t, h, 1)
}

// An observation consumer must never hold up the session lock.
type pausedInventory struct {
	*inventory.Inventory
	entered, release chan struct{}
}

func (p *pausedInventory) ObserveIEC104(o inventory.IEC104Observation) {
	close(p.entered)
	<-p.release
	p.Inventory.ObserveIEC104(o)
}

func TestIECInventoryObservationOutsideSessionLock(t *testing.T) {
	h := newAPCIHarness(t, "enforce")
	h.handshake()
	input := &pausedInventory{Inventory: h.e.Inventory(), entered: make(chan struct{}), release: make(chan struct{})}
	h.e.sessions.inventory = input
	p := h.pkt(true, capture.TCPFlagACK, h.cSeq, h.sSeq, apdu(46, 6, 1, 101, 2))
	done := make(chan capture.Decision, 1)
	go func() { done <- h.e.handlePacket(p) }()
	<-input.entered
	unlocked := h.e.sessions.mu.TryLock()
	if unlocked {
		h.e.sessions.mu.Unlock()
	}
	close(input.release)
	d := <-done
	if !unlocked {
		t.Fatal("inventory consumer ran under the session lock")
	}
	if d.Action != capture.Repeat {
		t.Fatal(d)
	}
	inventoryAttempts(t, h, 1)
}

func TestIECInventoryStartupCapture(t *testing.T) {
	for _, mode := range []string{"monitor", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			h := newAPCIHarness(t, mode)
			data, err := os.ReadFile("../../../test/iec104/testdata/startup-gi-monitor.pcap")
			if err != nil {
				t.Fatal(err)
			}
			for pos := 24; pos < len(data); {
				hdr := data[pos : pos+16]
				size := int(binary.LittleEndian.Uint32(hdr[8:12]))
				pos += 16
				frame := data[pos : pos+size]
				pos += size
				if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
					continue
				}
				p := capture.DecodeIPPacket(frame[14:])
				markHandshake(&p) // as nft queues the capture's handshake
				p.Queue = capturedIECQueue(p)
				h.clock = time.Unix(int64(binary.LittleEndian.Uint32(hdr)), int64(binary.LittleEndian.Uint32(hdr[4:8]))*1000)
				p.Timestamp = h.clock
				p.Token = h.token()
				d := h.e.handlePacket(p)
				v := capture.VerdictRepeat
				if d.Action == capture.Drop {
					v = capture.VerdictDrop
				}
				if d.Action != capture.Hold && (d.Notify || d.Action == capture.Drop) {
					h.e.hooks.onVerdict(p.Token, v, nil)
				}
				for _, r := range d.Resolved {
					h.e.hooks.onVerdict(r.Token, r.Verdict, nil)
				}
			}
			s := h.e.Inventory().SnapshotIEC104()
			if len(s.Pairs) != 3 {
				t.Fatalf("no station/CA: %+v", s)
			}
			points := 0
			var attempted uint64
			for _, pair := range s.Pairs {
				if len(pair.CAs) != 1 || pair.CAs[0].CA != 1 {
					t.Fatalf("wrong CAs: %+v", pair)
				}
				attempted += pair.AttemptedCommands
				points += len(pair.CAs[0].Points)
			}
			if points != 13 || attempted != 4 {
				t.Fatalf("vacuous capture replay: %+v", s)
			}
			t.Logf("%s: 3 pairs, 3 CAs, %d points, %d attempted commands", mode, points, attempted)
		})
	}
}
