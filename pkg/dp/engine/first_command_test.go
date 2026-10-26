// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// The tests in this file drive inline (NFQUEUE) packets through the real
// Modbus and DNP3 decoders under an enforce policy: default DENY, reads
// allowed, writes, diagnostics and operates denied. The first complete
// prohibited command must be dropped in its own packet's verdict, however
// the client segments it and whatever the dynamic-block updater does after
// the drop. Allowed commands on the same flow must be accepted, so a policy
// that blackholes the whole port cannot pass.

// firstCommandPolicy is the enforce policy every case runs under.
func firstCommandPolicy() rules.Snapshot {
	return rules.Snapshot{
		Default: rules.ActionDeny,
		Firewall: []rules.Entry{
			clientToServer("modbus-read", "502", rules.ActionAllow,
				rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}, ReadOnly: true}),
			clientToServer("modbus-write-deny", "502", rules.ActionDeny,
				rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{6}, WriteOnly: true}),
			clientToServer("modbus-diag-deny", "502", rules.ActionDeny,
				rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{8}}),
			clientToServer("dnp3-read", "20000", rules.ActionAllow,
				rules.ICSPredicate{Protocol: "dnp3", FunctionCode: []uint8{1}}),
			clientToServer("dnp3-operate-deny", "20000", rules.ActionDeny,
				rules.ICSPredicate{Protocol: "dnp3", FunctionCode: []uint8{5, 6}}),
		},
	}
}

// dnp3CRC is the DNP3 link CRC (CRC-16/DNP: reflected 0x3D65, inverted).
func dnp3CRC(b []byte) uint16 {
	var crc uint16
	for _, c := range b {
		crc ^= uint16(c)
		for range 8 {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xA6BC
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

// dnp3Request is a single-fragment request link frame from master 1 to
// outstation 10: transport and application headers, function code fc and
// the object bytes, in CRC-terminated blocks of at most 16 octets.
func dnp3Request(fc, appSeq uint8, objects []byte) []byte {
	user := append([]byte{0xC0, 0xC0 | appSeq, fc}, objects...)
	frame := []byte{0x05, 0x64, byte(5 + len(user)), 0xC4, 10, 0, 1, 0}
	frame = binary.LittleEndian.AppendUint16(frame, dnp3CRC(frame))
	for len(user) > 0 {
		block := user[:min(16, len(user))]
		user = user[len(block):]
		frame = append(frame, block...)
		frame = binary.LittleEndian.AppendUint16(frame, dnp3CRC(block))
	}
	return frame
}

// dnp3Operate is a control relay output block (g12v1, one point, index 0,
// latch on) operated with fc.
func dnp3Operate(fc, appSeq uint8) []byte {
	return dnp3Request(fc, appSeq, []byte{
		0x0C, 0x01, 0x17, 0x01, 0x00, // g12v1, 1-octet count and index: 1 object, index 0
		0x03, 0x01, 0x64, 0, 0, 0, 0, 0, 0, 0, 0x00, // latch on, once, 100 ms on, 0 off, status 0
	})
}

type firstCommand struct {
	name  string
	rule  string // the deny rule it must hit
	frame []byte
}

type firstCommandProtocol struct {
	name   string
	port   uint16
	read   func(n uint16) []byte // the n-th allowed read
	denied []firstCommand
}

func firstCommandProtocols() []firstCommandProtocol {
	return []firstCommandProtocol{
		{
			name: "modbus", port: 502,
			read: func(n uint16) []byte { return modbusADU(n, 3, 0, 2) },
			denied: []firstCommand{
				{"fc6 write", "modbus-write-deny", modbusADU(100, 6, 1, 0x1234)},
				{"fc8 diagnostics", "modbus-diag-deny", modbusADU(101, 8, 0, 0xA537)},
			},
		},
		{
			name: "dnp3", port: dnp3Port,
			read: func(n uint16) []byte { return dnp3Request(1, uint8(n%16), []byte{0x3C, 0x01, 0x06}) },
			denied: []firstCommand{
				{"fc5 direct operate", "dnp3-operate-deny", dnp3Operate(5, 9)},
				{"fc6 direct operate no ack", "dnp3-operate-deny", dnp3Operate(6, 10)},
			},
		},
	}
}

// TestFirstCommandDNP3FramesValid checks the frame builder against the
// independently encoded class 0 read used by the reply tests.
func TestFirstCommandDNP3FramesValid(t *testing.T) {
	if got := dnp3Request(1, 1, []byte{0x3C, 0x01, 0x06}); string(got) != string(dnp3Read) {
		t.Fatalf("dnp3Request = % x, want % x", got, dnp3Read)
	}
}

// firstCommandUpdater installs dynamic blocks as configured: at once, with
// an error, or never returning until the test ends. Every call is reported
// on calls before it returns or stalls.
type firstCommandUpdater struct {
	mode    string // "ok", "failing" or "stalled"
	calls   chan string
	release chan struct{}
}

func (u *firstCommandUpdater) BlockHostTemp(context.Context, net.IP, time.Duration) error {
	return errors.New("unexpected host block")
}

func (u *firstCommandUpdater) BlockFlowTemp(_ context.Context, src, dst net.IP, proto, dport string, _ time.Duration) error {
	u.calls <- src.String() + ">" + dst.String() + "/" + proto + ":" + dport
	switch u.mode {
	case "failing":
		return errors.New("nft: permission denied")
	case "stalled":
		<-u.release
	}
	return nil
}

// firstCommandEngine returns a started enforce engine whose packets carry
// inline tokens, as NFQUEUE delivers them.
func firstCommandEngine(t *testing.T, mode string) (*Engine, *firstCommandUpdater) {
	t.Helper()
	up := &firstCommandUpdater{mode: mode, calls: make(chan string, 16), release: make(chan struct{})}
	e, err := New(Config{
		Enforce:    EnforceConfig{Enabled: true, Updater: up},
		DPIEnabled: true,
		DPIMode:    "enforce",
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	e.capture = idleCapture{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { close(up.release) }) // runs before cancel
	e.LoadRules(firstCommandPolicy())
	return e, up
}

var firstCommandTokens atomic.Uint32

// fcFlow is one client connection to the protocol's server port. Offsets
// are relative to the first payload byte.
type fcFlow struct {
	t      *testing.T
	e      *Engine
	up     *firstCommandUpdater
	port   uint16
	client uint16
	isn    uint32
	next   uint32 // offset of the next new byte
	denies int    // DPI denials seen
}

func newFCFlow(t *testing.T, mode string, port uint16) *fcFlow {
	e, up := firstCommandEngine(t, mode)
	return &fcFlow{t: t, e: e, up: up, port: port, client: 41000, isn: 7000}
}

// decide hands one client segment to the engine as the inline capture does
// and completes its verdict.
func (f *fcFlow) decide(off uint32, flags capture.TCPFlags, payload []byte) capture.Decision {
	pkt := connSegment(false, f.client, f.port, f.isn+off, flags, payload)
	pkt.Token = capture.NewToken(1, firstCommandTokens.Add(1))
	d := f.e.HandlePacket(pkt)
	v := capture.VerdictAccept
	if d.Action == capture.Drop {
		v = capture.VerdictDrop
	}
	f.e.hooks.onVerdict(pkt.Token, v, nil)
	return d
}

func (f *fcFlow) syn() {
	f.t.Helper()
	if d := f.decide(0, capture.TCPFlagSYN, nil); d.Action != capture.Accept {
		f.t.Fatalf("SYN decision = %+v, want Accept", d)
	}
}

// accept sends payload as the next new bytes and requires Accept.
func (f *fcFlow) accept(what string, payload []byte) {
	f.t.Helper()
	f.acceptAt(f.next, what, payload)
	f.next += uint32(len(payload))
}

func (f *fcFlow) acceptAt(off uint32, what string, payload []byte) {
	f.t.Helper()
	if d := f.decide(off, ackPsh, payload); d.Action != capture.Accept {
		f.t.Fatalf("%s at offset %d: decision = %+v, want Accept", what, off, d)
	}
}

// deny sends payload as the next new bytes and requires the first DPI drop
// of the flow, by rule; the dynamic block follows the verdict.
func (f *fcFlow) deny(what, rule string, payload []byte) {
	f.t.Helper()
	f.denyAt(f.next, what, rule, payload)
	f.next += uint32(len(payload))
}

func (f *fcFlow) denyAt(off uint32, what, rule string, payload []byte) {
	f.t.Helper()
	hits := ruleHits(f.e, rule)
	if d := f.decide(off, ackPsh, payload); d.Action != capture.Drop || d.Reason != reasonDPIDeny {
		f.t.Fatalf("%s at offset %d: decision = %+v, want Drop by %s", what, off, d, reasonDPIDeny)
	}
	if got := ruleHits(f.e, rule); got != hits+1 {
		f.t.Fatalf("%s: rule %s hits %d -> %d, want one more", what, rule, hits, got)
	}
	f.denies++
	want := fmt.Sprintf("%s>%s/tcp:%d", testClient, testServer, f.port)
	select {
	case got := <-f.up.calls:
		if got != want {
			f.t.Fatalf("dynamic block %q, want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		f.t.Fatal("dynamic block was not attempted after the drop verdict")
	}
}

// dropCachedAt resends bytes at off and requires the cached denial's drop.
func (f *fcFlow) dropCachedAt(off uint32, what string, payload []byte) {
	f.t.Helper()
	if d := f.decide(off, ackPsh, payload); d.Action != capture.Drop || d.Reason != reasonCachedDeny {
		f.t.Fatalf("%s at offset %d: decision = %+v, want Drop by %s", what, off, d, reasonCachedDeny)
	}
}

func concatFrames(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

type firstCommandCase struct {
	name string
	run  func(f *fcFlow, p firstCommandProtocol, c firstCommand)
}

// firstCommandCases lists every segmentation of the prohibited command.
func firstCommandCases(denied []byte) []firstCommandCase {
	cases := []firstCommandCase{
		{"first payload of new flow", func(f *fcFlow, _ firstCommandProtocol, c firstCommand) {
			f.syn()
			f.deny("denied", c.rule, c.frame)
		}},
		{"first payload without handshake", func(f *fcFlow, _ firstCommandProtocol, c firstCommand) {
			f.deny("denied", c.rule, c.frame)
		}},
		{"after reads on the same flow", func(f *fcFlow, p firstCommandProtocol, c firstCommand) {
			f.syn()
			f.accept("read 1", p.read(1))
			f.accept("read 2", p.read(2))
			f.deny("denied", c.rule, c.frame)
			f.dropCachedAt(f.next, "read after denial", p.read(3))
		}},
		{"coalesced read then denied", func(f *fcFlow, p firstCommandProtocol, c firstCommand) {
			f.syn()
			f.deny("read+denied", c.rule, concatFrames(p.read(1), c.frame))
		}},
		{"coalesced denied then read", func(f *fcFlow, p firstCommandProtocol, c firstCommand) {
			f.syn()
			f.deny("denied+read", c.rule, concatFrames(c.frame, p.read(1)))
		}},
		{"retransmitted denied", func(f *fcFlow, p firstCommandProtocol, c firstCommand) {
			f.syn()
			f.accept("read", p.read(1))
			at := f.next
			f.deny("denied", c.rule, c.frame)
			for range 3 {
				f.dropCachedAt(at, "retransmitted denied", c.frame)
			}
		}},
		{"retransmitted read then denied", func(f *fcFlow, p firstCommandProtocol, c firstCommand) {
			f.syn()
			f.accept("read", p.read(1))
			f.acceptAt(0, "retransmitted read", p.read(1))
			f.deny("denied", c.rule, c.frame)
		}},
		{"one byte per segment", func(f *fcFlow, p firstCommandProtocol, c firstCommand) {
			f.syn()
			f.accept("read", p.read(1))
			for i := range len(c.frame) - 1 {
				f.accept(fmt.Sprintf("denied byte %d", i), c.frame[i:i+1])
			}
			f.deny("denied last byte", c.rule, c.frame[len(c.frame)-1:])
		}},
	}
	for k := 1; k < len(denied); k++ {
		cases = append(cases,
			firstCommandCase{fmt.Sprintf("split at %d", k), func(f *fcFlow, p firstCommandProtocol, c firstCommand) {
				f.syn()
				f.accept("read", p.read(1))
				f.accept("denied head", c.frame[:k])
				at := f.next
				f.deny("denied tail", c.rule, c.frame[k:])
				f.dropCachedAt(at, "retransmitted tail", c.frame[k:])
				f.dropCachedAt(at-uint32(k), "retransmitted whole command", c.frame)
			}},
			firstCommandCase{fmt.Sprintf("read coalesced with head split at %d", k), func(f *fcFlow, p firstCommandProtocol, c firstCommand) {
				f.syn()
				f.accept("read+denied head", concatFrames(p.read(1), c.frame[:k]))
				f.deny("denied tail", c.rule, c.frame[k:])
			}},
			firstCommandCase{fmt.Sprintf("tail before head split at %d", k), func(f *fcFlow, p firstCommandProtocol, c firstCommand) {
				f.syn()
				f.accept("read", p.read(1))
				head := f.next
				f.acceptAt(head+uint32(k), "out-of-order tail", c.frame[k:])
				f.denyAt(head, "head", c.rule, c.frame[:k])
				f.next = head + uint32(len(c.frame))
			}},
		)
	}
	return cases
}

// TestFirstCommandDroppedInline is the first-command matrix: every
// protocol, prohibited command, segmentation and updater behaviour.
func TestFirstCommandDroppedInline(t *testing.T) {
	for _, mode := range []string{"ok", "failing", "stalled"} {
		t.Run("updater "+mode, func(t *testing.T) {
			for _, p := range firstCommandProtocols() {
				t.Run(p.name, func(t *testing.T) {
					for _, c := range p.denied {
						t.Run(c.name, func(t *testing.T) {
							for _, tc := range firstCommandCases(c.frame) {
								t.Run(tc.name, func(t *testing.T) {
									f := newFCFlow(t, mode, p.port)
									tc.run(f, p, c)
									if f.denies != 1 {
										t.Fatalf("DPI denials = %d, want 1", f.denies)
									}
								})
							}
						})
					}
				})
			}
		})
	}
}

// TestFirstCommandReadsAccepted is the positive control: on a flow that
// only reads, in any segmentation, nothing is dropped and no block is
// attempted.
func TestFirstCommandReadsAccepted(t *testing.T) {
	for _, p := range firstCommandProtocols() {
		t.Run(p.name, func(t *testing.T) {
			f := newFCFlow(t, "ok", p.port)
			f.syn()
			f.accept("read 1", p.read(1))
			f.accept("reads 2+3", concatFrames(p.read(2), p.read(3)))
			r := p.read(4)
			f.accept("read 4 head", r[:5])
			f.accept("read 4 tail", r[5:])
			f.acceptAt(0, "retransmitted read 1", p.read(1))
			if got := ruleHits(f.e, p.name+"-read"); got != 4 {
				t.Fatalf("read rule hits = %d, want 4", got)
			}
			select {
			case got := <-f.up.calls:
				t.Fatalf("dynamic block %q on a read-only flow", got)
			default:
			}
		})
	}
}
