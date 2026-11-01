// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/inventory"
)

type inventoryHarness struct {
	*iecHarness
	delivered atomic.Uint64
}

func newInventoryHarness(t *testing.T, mode string) *inventoryHarness {
	h := &inventoryHarness{iecHarness: newAPCIHarness(t, mode)}
	learn := h.e.iec.learnDelivery
	h.e.iec.learnDelivery = func(id string) {
		h.delivered.Add(1)
		learn(id)
	}
	return h
}

func inventoryCounts(t *testing.T, h *inventoryHarness, attempted, delivered uint64) {
	t.Helper()
	s := h.e.Inventory().SnapshotIEC104()
	if len(s.Pairs) != 1 || s.Pairs[0].AttemptedCommands != attempted || h.delivered.Load() != delivered {
		t.Fatalf("want %d attempts/%d learner deliveries, got %d deliveries: %+v", attempted, delivered, h.delivered.Load(), s)
	}
}

func TestIECInventoryDelivery(t *testing.T) {
	for _, fate := range []string{"accept", "repeat", "deny", "error", "drop", "queue", "monitor", "not-inline", "would-drop"} {
		t.Run(fate, func(t *testing.T) {
			mode := "enforce"
			if fate == "monitor" {
				mode = "monitor"
			}
			h := newInventoryHarness(t, mode)
			if fate == "deny" || fate == "would-drop" {
				h.e.iec.policy = h.policy
				h.policy.allowType = 100 // deny command type 46
				if fate == "would-drop" {
					h.policy.mode = "monitor"
					h.e.LoadRules(iecSnapshot("monitor"))
				}
			}
			h.handshake()
			p := h.pkt(true, capture.TCPFlagACK, h.cSeq, h.sSeq, apdu(46, 6, 7, 101, 2))
			if fate == "not-inline" {
				p.Token = capture.Token{}
			}
			d := h.e.handlePacket(p)
			inventoryCounts(t, h, 1, 0)
			v, err := capture.VerdictAccept, error(nil)
			switch fate {
			case "repeat":
				// A successful repeat is only a kernel continuation, never
				// proof of delivery (S2 can still deny).
				v = capture.VerdictRepeat
			case "error":
				err = errors.New("sendmsg failed")
			case "drop", "deny":
				v = capture.VerdictDrop
			case "queue":
				v, err = capture.VerdictDrop, capture.ErrQueueClosed
			}
			h.e.hooks.onVerdict(p.Token, v, err)
			// Duplicate completions cannot credit twice, including after failure.
			h.e.hooks.onVerdict(p.Token, capture.VerdictAccept, nil)
			want := uint64(0)
			if fate == "accept" {
				want = 1
				if !d.Notify {
					t.Fatal("immediate command accept needs a completion")
				}
			}
			inventoryCounts(t, h, 1, want)
			if (d.Action == capture.Drop) != (fate == "deny") {
				t.Fatalf("decision changed: %+v", d)
			}
		})
	}
}

func TestIECInventorySplitCoalescedOutOfOrderAndRetransmit(t *testing.T) {
	h := newInventoryHarness(t, "enforce")
	h.handshake()
	// Two commands plus a partial next APDU keep even decoded commands held.
	cmd := apdu(46, 6, 1, 101, 2)
	payload := append(append(append([]byte{}, cmd...), cmd...), 0x68)
	seq := h.cSeq
	var packets []capture.Packet
	for _, r := range [][2]int{{9, len(payload)}, {9, len(payload)}, {0, 9}} {
		p := h.pkt(true, capture.TCPFlagACK, seq+uint32(r[0]), h.sSeq, payload[r[0]:r[1]])
		packets = append(packets, p)
		d := h.e.handlePacket(p)
		if r[0] == 9 && d.Action != capture.Hold || r[0] == 0 && d.Action != capture.Repeat {
			t.Fatalf("unexpected split disposition: %+v", d)
		}
	}
	inventoryCounts(t, h, 2, 0)
	// A retransmission while commands are pending is carrying evidence too.
	p := h.pkt(true, capture.TCPFlagACK, seq, h.sSeq, payload[:9])
	packets = append(packets, p)
	h.e.handlePacket(p)
	// Finish the partial U-frame so the real decision releases the tail
	// packets; only then simulate capture's successful verdict completions.
	release := h.e.handlePacket(h.pkt(true, capture.TCPFlagACK, seq+uint32(len(payload)), h.sSeq, startdtAct[1:]))
	if release.Action != capture.Repeat || len(release.Resolved) != 2 {
		t.Fatalf("held tails were not released: %+v", release)
	}
	for _, p := range packets[:len(packets)-1] {
		h.e.hooks.onVerdict(p.Token, capture.VerdictAccept, nil)
	}
	inventoryCounts(t, h, 2, 1) // second command did not overlap the retransmitted head
	h.e.hooks.onVerdict(p.Token, capture.VerdictAccept, nil)
	inventoryCounts(t, h, 2, 2)
	h.e.handlePacket(h.pkt(true, capture.TCPFlagACK, seq, h.sSeq, payload[:len(payload)-1]))
	inventoryCounts(t, h, 2, 2) // completed retransmission is not a new APDU
}

func TestIECInventoryAbortWhileCommandHeld(t *testing.T) {
	h := newInventoryHarness(t, "enforce")
	h.handshake()
	cmd := apdu(46, 6, 1, 101, 2)
	p, d := h.send(true, append(cmd, 0x68))
	if d.Action != capture.Hold {
		t.Fatal(d)
	}
	inventoryCounts(t, h, 1, 0)
	h.e.iec.onSourceDown()
	h.e.hooks.onVerdict(p.Token, capture.VerdictAccept, nil)
	inventoryCounts(t, h, 1, 0)
	if len(h.e.iec.inventoryTokens) != 0 {
		t.Fatal("aborted ledger retained tokens")
	}
}

func TestIECInventoryDroppedRetransmissionBeforeCompletion(t *testing.T) {
	h := newInventoryHarness(t, "enforce")
	h.handshake()
	p, _ := h.send(true, apdu(46, 6, 1, 101, 2))
	original := p.Token
	// An ACK can be processed before capture's original successful verdict
	// notification. History is already released, so the retransmit drops.
	h.send(false, nil)
	p.Token = h.token()
	if d := h.e.handlePacket(p); d.Action != capture.Drop {
		t.Fatalf("expected below-floor drop: %+v", d)
	}
	h.e.hooks.onVerdict(p.Token, capture.VerdictDrop, nil)
	h.e.hooks.onVerdict(original, capture.VerdictAccept, nil)
	inventoryCounts(t, h, 1, 0)
}

func TestIECInventoryBoundsAndAgeOut(t *testing.T) {
	for _, bound := range []string{"commands", "tokens"} {
		t.Run(bound, func(t *testing.T) {
			h := newInventoryHarness(t, "enforce")
			h.handshake()
			cmd := apdu(46, 6, 1, 101, 2)
			if bound == "commands" {
				for i := 0; i <= iecInventoryCap; i++ {
					h.send(true, cmd)
				}
			} else {
				p, _ := h.send(true, cmd)
				for i := 0; i < iecInventoryCap; i++ {
					p.Token = h.token()
					h.e.handlePacket(p)
				}
			}
			snap := h.e.Inventory().SnapshotIEC104()
			attempts, pending := uint64(1), 0
			if bound == "commands" {
				attempts, pending = iecInventoryCap+1, iecInventoryCap
			}
			if snap.Pairs[0].AttemptedCommands != attempts || h.delivered.Load() != 0 {
				t.Fatalf("bounded learner evidence changed: %+v", snap)
			}
			for _, s := range h.e.iec.sessions {
				if len(s.inventory.commands) != pending || len(s.inventory.tokens) != pending {
					t.Fatalf("want %d pending commands/tokens; got %d/%d", pending, len(s.inventory.commands), len(s.inventory.tokens))
				}
			}
			h.clock = h.clock.Add(iecPendingTimeout + time.Nanosecond)
			h.e.iec.expire()
			if len(h.e.iec.inventoryTokens) != 0 {
				t.Fatal("pending delivery did not age out")
			}
		})
	}
}

func TestIECInventorySessionEnds(t *testing.T) {
	for _, end := range []string{"close", "abort", "delete", "policy", "idle", "stop", "reconfigure"} {
		t.Run(end, func(t *testing.T) {
			h := newInventoryHarness(t, "enforce")
			h.handshake()
			p, _ := h.send(true, apdu(46, 6, 1, 101, 2))
			old := h.e.iec
			var s *iecSession
			for _, candidate := range old.sessions {
				s = candidate
			}
			var acts iecActions
			old.mu.Lock()
			switch end {
			case "close":
				acts = old.closeLocked(s, h.clock)
			case "abort":
				acts = old.abortLocked(s, abortPolicy, "", nil, h.clock)
			case "delete":
				acts = old.deleteLocked(iecKey{s.client, s.server}, s)
			}
			old.mu.Unlock()
			old.finish(acts)
			switch end {
			case "policy":
				h.policy.matched = false
				h.e.LoadRules(iecSnapshot("enforce"))
			case "idle":
				h.clock = h.clock.Add(iecIdleTTL + time.Second)
				old.expire()
			case "stop":
				stop := make(chan struct{})
				close(stop)
				old.run(stop)
			case "reconfigure":
				h.e.Reconfigure(newAPCIHarness(t, "enforce").e)
			}
			old.onVerdict(p.Token, capture.VerdictAccept, nil)
			if s.inventory != nil || len(old.inventoryTokens) != 0 {
				t.Fatal("session end retained inventory ledger")
			}
		})
	}
}

// Pause the observation API after table unlock, then complete from another
// capture worker. No waiting for an observation, no early or duplicate outcome.
type pausedInventory struct {
	*inventory.Inventory
	entered, release chan struct{}
	observed         atomic.Bool
}

func (p *pausedInventory) ObserveIEC104(o inventory.IEC104Observation) {
	close(p.entered)
	<-p.release
	p.Inventory.ObserveIEC104(o)
	p.observed.Store(true)
}

func TestIECInventoryConcurrentObservationOutcomeExactlyOnce(t *testing.T) {
	for _, fate := range []string{"accept", "abort", "close"} {
		t.Run(fate, func(t *testing.T) {
			h := newInventoryHarness(t, "enforce")
			h.handshake()
			input := &pausedInventory{Inventory: h.e.Inventory(), entered: make(chan struct{}), release: make(chan struct{})}
			h.e.iec.inventory = input
			var early atomic.Bool
			learn := h.e.iec.learnDelivery
			h.e.iec.learnDelivery = func(id string) {
				if !input.observed.Load() {
					early.Store(true)
				}
				learn(id)
			}
			p := h.pkt(true, capture.TCPFlagACK, h.cSeq, h.sSeq, apdu(46, 6, 1, 101, 2))
			var wg sync.WaitGroup
			wg.Go(func() { h.e.handlePacket(p) })
			<-input.entered
			if fate != "accept" {
				h.e.iec.mu.Lock()
				var acts iecActions
				for _, s := range h.e.iec.sessions {
					if fate == "abort" {
						acts.merge(h.e.iec.abortLocked(s, abortPolicy, "", nil, h.clock))
					} else {
						acts.merge(h.e.iec.closeLocked(s, h.clock))
					}
				}
				h.e.iec.mu.Unlock()
				h.e.iec.finish(acts)
			}
			for i := 0; i < 8; i++ {
				wg.Go(func() { h.e.hooks.onVerdict(p.Token, capture.VerdictAccept, nil) })
			}
			// A completion must return while observation is paused.
			h.e.hooks.onVerdict(p.Token, capture.VerdictAccept, nil)
			if h.delivered.Load() != 0 {
				t.Fatal("outcome preceded observation")
			}
			close(input.release)
			wg.Wait()
			if early.Load() {
				t.Fatal("learner delivery preceded observation")
			}
			want := uint64(0)
			if fate == "accept" {
				want = 1
			}
			inventoryCounts(t, h, 1, want)
		})
	}
}

func TestIECInventoryStartupCapture(t *testing.T) {
	for _, mode := range []string{"monitor", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			h := newInventoryHarness(t, mode)
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
				h.clock = time.Unix(int64(binary.LittleEndian.Uint32(hdr)), int64(binary.LittleEndian.Uint32(hdr[4:8]))*1000)
				p.Timestamp = h.clock
				p.Token = h.token()
				d := h.e.handlePacket(p)
				v := capture.VerdictAccept
				if d.Action == capture.Drop {
					v = capture.VerdictDrop
				}
				if d.Action != capture.Hold {
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
			want := uint64(0)
			if mode == "enforce" {
				want = 4
			}
			if h.delivered.Load() != want {
				t.Fatalf("learner deliveries %d, want %d", h.delivered.Load(), want)
			}
			t.Logf("%s: 3 pairs, 3 CAs, %d points, %d attempted / %d learner deliveries", mode, points, attempted, h.delivered.Load())
		})
	}
}
