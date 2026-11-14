// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
)

func TestDS34ReconnectLifecycle(t *testing.T) {
	t.Run("half-close-keeps-opposite-reply-only", func(t *testing.T) {
		f := newResetFlow(t, 502)
		f.syn()
		f.accept("request before half-close", modbusADU(1, 3, 0, 2))
		if d := f.handle(f.segment(false, f.isn+f.next, resyncServerISN, finAck, nil)); d.Action != capture.Repeat {
			t.Fatal(d)
		}
		reply := []byte{0, 1, 0, 0, 0, 7, 1, 3, 4, 0, 10, 0, 11}
		if d := f.handle(f.segment(true, resyncServerISN, f.isn+f.next+1, ackPsh, reply)); d.Action != capture.Repeat {
			t.Fatalf("authorized opposite-direction reply after FIN = %+v", d)
		}
		if d := f.handle(f.segment(false, f.isn+f.next+1, resyncServerISN+uint32(len(reply)), ackPsh, modbusADU(2, 3, 0, 2))); d.Action != capture.Drop {
			t.Fatalf("new bytes after forwarded FIN = %+v", d)
		}
		f.waitResets(2)
	})
	t.Run("proposal-preserves-grants-and-holds", func(t *testing.T) {
		f := newResetFlow(t, 502)
		f.syn()
		f.accept("authorized opener", modbusADU(1, 3, 0, 2))
		f.hold("second request prefix", modbusADU(2, 3, 0, 2)[:3])
		tab := f.e.sessions
		client, server := f.endpoints()
		tab.mu.Lock()
		old, _ := tab.lookupLocked(client, server)
		id := old.id
		tab.mu.Unlock()
		syn := f.segment(false, 800000, 0, capture.TCPFlagSYN, nil)
		if d := f.handle(syn); d.Action != capture.Repeat || len(d.Resolved) != 0 {
			t.Fatalf("replacement SYN = %+v", d)
		}
		tab.mu.Lock()
		current, _ := tab.lookupLocked(client, server)
		grants := current.pairing.(*pairLedger[modbusPairKey, modbus.PairShape]).grants
		preserved := current == old && current.id == id && len(grants) == 1 && len(current.held) == 1 && current.next != nil
		tab.mu.Unlock()
		if !preserved {
			t.Fatal("a bare SYN retired authority or released a partial request")
		}
		ack := f.segment(true, resyncServerISN+1000, 800000, capture.TCPFlagSYN|capture.TCPFlagACK, nil)
		d := f.handle(ack)
		if d.Action != capture.Repeat || len(d.Resolved) != 1 || d.Resolved[0].Verdict != capture.VerdictDrop {
			t.Fatalf("replacement handshake = %+v", d)
		}
		for _, r := range d.Resolved {
			f.e.hooks.onVerdict(r.Token, r.Verdict, nil)
		}
		tab.mu.Lock()
		current, _ = tab.lookupLocked(client, server)
		retired := current != old && current.id != id && current.state == sessionEstablished &&
			len(old.pairing.(*pairLedger[modbusPairKey, modbus.PairShape]).grants) == 0 &&
			len(current.pairing.(*pairLedger[modbusPairKey, modbus.PairShape]).grants) == 0 &&
			len(tab.settlements) == 0
		tab.mu.Unlock()
		if !retired {
			t.Fatal("proven replacement retained old grants or held residency")
		}
		drainResetWorker(t, f.e)
		if len(f.inj.Resets()) != 0 {
			t.Fatal("replacement reset the new peer connection")
		}
	})
	for _, retire := range []bool{false, true} {
		name := "reset-io-before-reuse"
		if retire {
			name = "expiry-pins-reset-io"
		}
		t.Run(name, func(t *testing.T) {
			f := newResetFlow(t, 502)
			started, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			t.Cleanup(unblock)
			f.e.sessions.ctDelete = func(context.Context, conntrack.DeleteRequest) error {
				close(started)
				<-release
				return nil
			}
			f.syn()
			if d := f.handle(f.segment(false, f.isn, resyncServerISN, ackPsh, modbusADU(1, 6, 1, 2))); d.Action != capture.Drop {
				t.Fatal(d)
			}
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("old reset did not reach conntrack I/O")
			}
			tab := f.e.sessions
			client, server := f.endpoints()
			tab.mu.Lock()
			old, _ := tab.lookupLocked(client, server)
			if retire {
				tab.deleteLocked(sessionKey{client, server}, old)
			}
			pinned := old.resetIO != nil && tab.sessions[sessionKey{client, server}] == old
			tab.mu.Unlock()
			if !pinned {
				t.Fatal("old I/O lost its tuple reservation")
			}
			f.isn, f.next = 800000, 0
			done := make(chan capture.Decision, 1)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				done <- f.handle(f.segment(false, f.isn, 0, capture.TCPFlagSYN, nil))
			}()
			t.Cleanup(func() {
				unblock()
				select {
				case <-finished:
				case <-time.After(2 * time.Second):
					t.Error("replacement handler did not join")
				}
			})
			select {
			case d := <-done:
				t.Fatalf("new SYN crossed unfinished old conntrack I/O: %+v", d)
			case <-time.After(20 * time.Millisecond):
			}
			unblock()
			select {
			case d := <-done:
				if d.Action != capture.Repeat {
					t.Fatal(d)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("new SYN did not resume after old I/O")
			}
			f.synAck()
			f.accept("new incarnation progresses", modbusADU(2, 3, 0, 2))
			drainResetWorker(t, f.e)
			if len(f.inj.Resets()) != 2 {
				t.Fatal("old reset job ran against the replacement")
			}
		})
	}
}
