// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/session"
)

func drainResetWorker(t *testing.T, e *Engine) {
	t.Helper()
	done := make(chan struct{})
	if !e.hooks.blocks.submit(func() { close(done) }) {
		t.Fatal("follow-up worker full")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("follow-up worker did not drain")
	}
}

func assertResetEvidence(t *testing.T, e *Engine) {
	t.Helper()
	drainResetWorker(t, e)
	targets := map[string]bool{}
	for _, ev := range e.Events().List(0) {
		if ev.Kind == eventfields.KindSession && (ev.Attributes[eventfields.KeyOutcome] == outcomeResetSent || ev.Attributes[eventfields.KeyOutcome] == "unavailable") {
			target, _ := ev.Attributes[eventfields.KeyTarget].(string)
			targets[target] = true
		}
	}
	if !targets["client"] || !targets["server"] {
		t.Fatalf("missing per-peer reset outcome evidence: %v", targets)
	}
}

// cipCommand builds SendRRData carrying a single CIP service, without a path.
func cipCommand(service byte) []byte {
	b := make([]byte, 38)
	binary.LittleEndian.PutUint16(b, 0x6f)
	binary.LittleEndian.PutUint16(b[2:], 14)
	binary.LittleEndian.PutUint16(b[30:], 1)
	binary.LittleEndian.PutUint16(b[32:], 0xb2)
	binary.LittleEndian.PutUint16(b[34:], 2)
	b[36] = service
	return b
}

func resetProtocols() []firstCommandProtocol {
	p := firstCommandProtocols()
	return append(p, firstCommandProtocol{name: "cip", port: 44818,
		read:   func(uint16) []byte { return cipCommand(0x0e) },
		denied: []firstCommand{{"set attribute", "cip-deny", cipCommand(0x10)}}})
}

func loadResetPolicy(e *Engine) {
	snap := firstCommandPolicy()
	snap.Firewall = append(snap.Firewall,
		clientToServer("cip-read", "44818", rules.ActionAllow, rules.ICSPredicate{Protocol: "cip", FunctionCode: []uint8{0x0e}}),
		clientToServer("cip-deny", "44818", rules.ActionDeny, rules.ICSPredicate{Protocol: "cip", FunctionCode: []uint8{0x10}}))
	e.LoadRules(snap)
}

func TestDenyResetReconnect(t *testing.T) {
	for _, p := range resetProtocols() {
		t.Run(p.name, func(t *testing.T) {
			f := newResetFlow(t, p.port)
			loadResetPolicy(f.e)
			f.syn()
			f.synAck()
			f.accept("read", p.read(1))

			// An independent session is already open to the very same service.
			other := *f.fcFlow
			other.client++
			other.syn()
			other.accept("concurrent read", p.read(1))
			at := f.next
			pkt := f.segment(false, f.isn+at, 9000, ackPsh, p.denied[0].frame)
			pkt.Token = capture.NewToken(1, firstCommandTokens.Add(1))
			if d := f.e.HandlePacket(pkt); d.Action != capture.Drop {
				t.Fatalf("denied command = %+v", d)
			}
			drainResetWorker(t, f.e)
			if len(f.inj.Resets()) != 0 {
				t.Fatal("reset sent before drop completion")
			}
			f.e.hooks.onVerdict(pkt.Token, capture.VerdictDrop, nil)
			client, server := f.endpoints()
			want := []session.Reset{{Src: client, Dst: server, Seq: pkt.TCP.Seq}, {Src: server, Dst: client, Seq: 9000}}
			if got := f.waitResets(2); !reflect.DeepEqual(got, want) {
				t.Fatalf("resets %+v, want %+v", got, want)
			}
			assertResetEvidence(t, f.e)
			for _, ev := range f.e.Events().List(0) {
				if ev.Kind == eventfields.KindSession && ev.Proto != p.name {
					t.Fatalf("reset protocol %q, want %q", ev.Proto, p.name)
				}
			}
			reversedSYN := f.segment(true, 123456, 0, capture.TCPFlagSYN, nil)
			reversedSYN.HasMark, reversedSYN.Mark = false, 0
			if d := f.handle(reversedSYN); d.Action != capture.Drop {
				t.Fatalf("reversed orientation SYN = %+v", d)
			}
			// Expire/evict the entire verdict cache, not the tuple tombstone.
			other.accept("concurrent session survives denial", p.read(2))
			f.e.verdictCache = NewVerdictCache(time.Nanosecond, 1)
			// Forget idle flows without also advancing the independent,
			// short-lived tombstone past its lifetime.
			f.e.flowMu.Lock()
			for _, st := range f.e.flows {
				st.IdleTimeout = time.Nanosecond
			}
			f.e.flowMu.Unlock()
			f.e.sweepFlows(time.Now().Add(time.Millisecond))
			if d := f.handle(pkt); d.Action != capture.Drop {
				t.Fatalf("retransmitted denied command = %+v", d)
			}
			// A flow sweep also forgot the allowed stream: re-establish it
			// separately before testing isolation of the same-port reconnect.
			other.isn, other.next = 600000, 0
			other.syn()
			other.accept("independent session", p.read(2))
			staleSYN := f.segment(false, f.isn, 0, capture.TCPFlagSYN, nil)
			if d := f.handle(staleSYN); d.Action != capture.Drop {
				t.Fatalf("old-incarnation SYN = %+v", d)
			}
			f.isn, f.next = 800000, 0
			f.syn()
			f.synAck()
			f.accept("same-port reconnect", p.read(3))
			other.accept("concurrent session survives", p.read(3))
			f.client += 2
			f.isn, f.next = 900000, 0
			f.syn()
			f.synAck()
			f.accept("new-port reconnect", p.read(4))
			drainResetWorker(t, f.e)
			if len(f.inj.Resets()) != 2 {
				t.Fatalf("unexpected resets: %+v", f.inj.Resets())
			}
			select {
			case got := <-f.up.calls:
				t.Fatalf("DPI installed block %s", got)
			default:
			}
		})
	}
}

func TestDenyResetActions(t *testing.T) {
	for _, p := range resetProtocols() {
		for _, mode := range []string{"deny", "reset", "default"} {
			t.Run(p.name+"/"+mode, func(t *testing.T) {
				f := newResetFlow(t, p.port)
				loadResetPolicy(f.e)
				snap := *f.e.CurrentRules()
				entries := make([]rules.Entry, 0, len(snap.Firewall))
				for _, entry := range snap.Firewall {
					if entry.ID == p.denied[0].rule {
						if mode == "default" {
							continue
						}
						if mode == "reset" {
							entry.Action = rules.ActionReset
						}
					}
					entries = append(entries, entry)
				}
				snap.Firewall = entries
				f.e.LoadRules(snap)
				f.syn()
				f.synAck()
				f.accept("allowed read", p.read(1))
				pkt := f.segment(false, f.isn+f.next, 9000, ackPsh, p.denied[0].frame)
				if mode == "default" {
					d := f.handle(pkt)
					if d.Action != capture.Repeat || d.Reason != reasonPolicyNonAdmit {
						t.Fatalf("default denial = %+v", d)
					}
					drainResetWorker(t, f.e)
					if len(f.inj.Resets()) != 0 {
						t.Fatal("ordinary default denial reset in userspace")
					}
					return
				}
				if d := f.handle(pkt); d.Action != capture.Drop || d.Reason != reasonDPIDeny {
					t.Fatalf("denial = %+v", d)
				}
				if got := f.waitResets(2); len(got) != 2 {
					t.Fatalf("resets %v", got)
				}
				assertResetEvidence(t, f.e)
				if len(f.up.calls) != 0 {
					t.Fatal("DPI installed a block")
				}
			})
		}
	}
}

func TestDenyConcurrentRetransmit(t *testing.T) {
	for _, p := range resetProtocols() {
		t.Run(p.name, func(t *testing.T) {
			f := newResetFlow(t, p.port)
			loadResetPolicy(f.e)
			f.syn()
			f.synAck()
			pkt := f.segment(false, f.isn, 9000, ackPsh, p.denied[0].frame)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					<-start
					if d := f.handle(pkt); d.Action != capture.Drop {
						t.Errorf("concurrent denied retransmission = %+v", d)
					}
				})
			}
			close(start)
			wg.Wait()
			if got := f.waitResets(2); len(got) != 2 {
				t.Fatalf("reset attempts %d, want one pair", len(got))
			}
			if len(f.up.calls) != 0 {
				t.Fatal("DPI installed a block")
			}
		})
	}
}

func TestDenyReconnectCancelsQueuedResetRetry(t *testing.T) {
	f := newResetFlow(t, 502)
	f.syn()
	f.synAck()
	pkt := f.segment(false, f.isn, 9000, ackPsh, modbusADU(1, 6, 1, 2))
	if d := f.handle(pkt); d.Action != capture.Drop {
		t.Fatalf("denied command = %+v", d)
	}
	f.waitResets(2)
	unblock := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(unblock) }) }
	t.Cleanup(release)
	if !f.e.hooks.blocks.submit(func() { <-unblock }) {
		t.Fatal("follow-up worker full")
	}
	f.handle(f.segment(true, 9000, f.isn+12, capture.TCPFlagACK, nil))
	f.isn, f.next = 800000, 0
	f.syn()
	f.synAck()
	f.accept("read on reconnected session", modbusADU(2, 3, 0, 2))
	release()
	drainResetWorker(t, f.e)
	if got := f.inj.Resets(); len(got) != 2 {
		t.Fatalf("queued old-incarnation retry sent after reconnect: %+v", got)
	}
}

func TestDenyResetRetiredBeforeDropCompletion(t *testing.T) {
	f := newResetFlow(t, 502)
	f.syn()
	pkt := f.segment(false, f.isn, 9000, ackPsh, modbusADU(1, 6, 1, 2))
	pkt.Token = capture.NewToken(1, firstCommandTokens.Add(1))
	if d := f.e.HandlePacket(pkt); d.Action != capture.Drop {
		t.Fatalf("denied command = %+v", d)
	}
	f.isn, f.next = 800000, 0
	f.syn()
	f.accept("read on new incarnation", modbusADU(2, 3, 0, 2))
	f.e.hooks.onVerdict(pkt.Token, capture.VerdictDrop, nil)
	drainResetWorker(t, f.e)
	n := 0
	for _, ev := range f.e.Events().List(0) {
		if ev.Kind == eventfields.KindSession && ev.Attributes[eventfields.KeyOutcome] == "unavailable" {
			n++
		}
	}
	if len(f.inj.Resets()) != 0 || len(f.deletes) != 0 || n != 2 {
		t.Fatalf("retired reset: resets=%v deletes=%d unavailable=%d", f.inj.Resets(), len(f.deletes), n)
	}
}

func TestDenyResetUnavailable(t *testing.T) {
	for _, p := range resetProtocols() {
		for _, mode := range []string{"injector", "IPv6", "send_failure"} {
			t.Run(p.name+"/"+mode, func(t *testing.T) {
				f := newResetFlow(t, p.port)
				readFC := map[string]uint8{"modbus": 3, "dnp3": 1, "cip": 0x0e}[p.name]
				// No address scope: both families exercise an explicit ICS
				// denial (ordinary defaults continue to kernel admission).
				f.e.LoadRules(rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{{
					ID: "reads", Protocols: []rules.Protocol{{Name: "tcp", Port: strconv.Itoa(int(p.port))}},
					ICS: rules.ICSPredicate{Protocol: p.name, FunctionCode: []uint8{readFC}}, Action: rules.ActionAllow,
				}}})
				snap := *f.e.CurrentRules()
				deny := snap.Firewall[0]
				deny.ID, deny.Action, deny.ICS.FunctionCode = "commands-denied", rules.ActionDeny, nil
				snap.Firewall = append(snap.Firewall, deny)
				f.e.LoadRules(snap)
				pkt := f.segment(false, 7000, 9000, ackPsh, p.denied[0].frame)
				switch mode {
				case "IPv6":
					pkt.SrcIP, pkt.DstIP = net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
					pkt.Queue = nil
				case "injector":
					f.e.iec.health.fault(faultInjector, "unavailable")
				case "send_failure":
					f.inj.SetError(errors.New("sendto: operation not permitted"))
				}
				syn := pkt
				syn.Payload, syn.TCP.Flags = nil, capture.TCPFlagSYN
				syn.TCP.Seq--
				markHandshake(&syn)
				if d := f.handle(syn); d.Action != capture.Repeat {
					t.Fatalf("SYN = %+v", d)
				}
				if d := f.handle(pkt); d.Action != capture.Drop || d.Reason != reasonDPIDeny {
					t.Fatalf("denial = %+v", d)
				}
				drainResetWorker(t, f.e)
				outcome := "unavailable"
				if mode == "send_failure" {
					outcome = outcomeResetFailed
					f.waitResets(2)
					if f.e.IEC104Enforcement().Healthy {
						t.Fatal("failed injection did not fault enforcement health")
					}
				} else if len(f.inj.Resets()) != 0 || len(f.deletes) != 0 {
					t.Fatalf("unavailable injector: resets=%v deletes=%d", f.inj.Resets(), len(f.deletes))
				}
				targets := map[string]bool{}
				for _, ev := range f.e.Events().List(0) {
					if ev.Kind == eventfields.KindSession && ev.Attributes[eventfields.KeyOutcome] == outcome {
						if ev.Proto != p.name {
							t.Fatalf("event protocol %q", ev.Proto)
						}
						target, _ := ev.Attributes[eventfields.KeyTarget].(string)
						targets[target] = true
						if mode == "send_failure" && ev.Attributes[eventfields.KeyError] == nil {
							t.Fatal("failed reset evidence lacks error")
						}
					}
				}
				if !targets["client"] || !targets["server"] || len(f.up.calls) != 0 {
					t.Fatalf("outcomes=%v blocks=%d", targets, len(f.up.calls))
				}
			})
		}
	}
}

func TestDenyUDPDatagramOnly(t *testing.T) {
	f := newResetFlow(t, 44818)
	f.e.LoadRules(rules.Snapshot{Default: rules.ActionAllow, Firewall: []rules.Entry{{
		ID: "cip-deny", Protocols: []rules.Protocol{{Name: "udp", Port: "44818"}},
		ICS: rules.ICSPredicate{Protocol: "cip", FunctionCode: []uint8{0x10}}, Action: rules.ActionDeny,
	}}})
	pkt := f.segment(false, 0, 0, 0, cipCommand(0x10))
	pkt.Proto, pkt.Transport, pkt.TCP = 17, "udp", capture.TCPMeta{}
	if d := f.handle(pkt); d.Action != capture.Drop {
		t.Fatalf("UDP denied datagram = %+v", d)
	}
	pkt.Payload = cipCommand(0x0e)
	if d := f.handle(pkt); d.Action != capture.Repeat {
		t.Fatalf("UDP next allowed datagram = %+v", d)
	}
	drainResetWorker(t, f.e)
	if len(f.inj.Resets()) != 0 || len(f.deletes) != 0 || len(f.up.calls) != 0 {
		t.Fatal("UDP deny had session/block side effects")
	}
}
