// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package dpi

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

type streamEndCall struct {
	session string
	dir     StreamDir
}

type statefulStreamDecoder struct {
	mu        sync.Mutex
	parsed    []streamEndCall
	ended     []streamEndCall
	parseFail bool
}

func (*statefulStreamDecoder) Supports(*flow.State) bool { return true }

func (*statefulStreamDecoder) OnPacket(*flow.State, *ParsedPacket) ([]Event, error) {
	return nil, nil
}

func (*statefulStreamDecoder) OnFlowEnd(*flow.State) ([]Event, error) {
	return nil, nil
}

func (*statefulStreamDecoder) Protocol() string { return "stateful" }

func (d *statefulStreamDecoder) ParseStream(_ *flow.State, view StreamView) (StreamResult, error) {
	d.mu.Lock()
	d.parsed = append(d.parsed, streamEndCall{session: view.Session, dir: view.Dir})
	fail := d.parseFail
	d.mu.Unlock()
	if fail {
		return StreamResult{}, &FrameError{Offset: view.Base, Reason: "test framing failure"}
	}
	return StreamResult{NeedMore: true}, nil
}

func (d *statefulStreamDecoder) StreamEnded(session string, dir StreamDir) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ended = append(d.ended, streamEndCall{session: session, dir: dir})
}

func (d *statefulStreamDecoder) calls() (parsed, ended []streamEndCall) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]streamEndCall(nil), d.parsed...), append([]streamEndCall(nil), d.ended...)
}

func streamEndState(id byte, reverse bool) *flow.State {
	key := flow.Key{
		SrcIP:   net.IPv4(192, 0, 2, id),
		DstIP:   net.IPv4(198, 51, 100, id),
		SrcPort: 40000 + uint16(id),
		DstPort: 20000 + uint16(id),
		Proto:   6,
	}
	if reverse {
		key = key.Reversed()
	}
	return flow.NewState(key, time.Now())
}

func legacyStreamPacket(dir StreamDir) *ParsedPacket {
	return &ParsedPacket{Proto: "tcp", Payload: []byte{0x42}, Dir: dir}
}

func assertStreamEndCalls(t *testing.T, d *statefulStreamDecoder, want ...streamEndCall) {
	t.Helper()
	_, got := d.calls()
	counts := make(map[streamEndCall]int)
	for _, call := range got {
		counts[call]++
	}
	expected := make(map[streamEndCall]int)
	for _, call := range want {
		expected[call]++
	}
	for call, count := range expected {
		if counts[call] != count {
			t.Errorf("StreamEnded(%q, %v) called %d times, want %d; calls=%+v", call.session, call.dir, counts[call], count, got)
		}
		delete(counts, call)
	}
	for call, count := range counts {
		if count != 0 {
			t.Errorf("unexpected StreamEnded(%q, %v) called %d times", call.session, call.dir, count)
		}
	}
}

func TestStreamEnderSessionEndDropsBothDirectionsOnce(t *testing.T) {
	decoder := &statefulStreamDecoder{}
	manager := NewManager(decoder)
	state := streamEndState(1, false)
	const session = "session-end-test"

	for _, dir := range []StreamDir{ClientToServer, ServerToClient} {
		manager.Inspect(state, sessionSeg(session, dir, 0, 0x42))
	}
	manager.EndStream(session)
	manager.EndStream(session)

	parsed, _ := decoder.calls()
	if len(parsed) != 2 {
		t.Fatalf("ParseStream calls = %d, want 2", len(parsed))
	}
	assertStreamEndCalls(t, decoder,
		streamEndCall{session: session, dir: ClientToServer},
		streamEndCall{session: session, dir: ServerToClient},
	)
}

func TestStreamEnderLegacyDiscardPaths(t *testing.T) {
	type endFunc func(*Manager, *flow.State, *ParsedPacket)
	tests := []struct {
		name      string
		end       endFunc
		parseFail bool
	}{
		{
			name: "close",
			end: func(manager *Manager, state *flow.State, _ *ParsedPacket) {
				_, _, err := manager.CloseStream(state, &ParsedPacket{Proto: "tcp", TCPFin: true})
				if err != nil {
					t.Errorf("CloseStream error: %v", err)
				}
				_, _, err = manager.CloseStream(state, &ParsedPacket{Proto: "tcp", TCPFin: true})
				if err != nil {
					t.Errorf("repeated CloseStream error: %v", err)
				}
			},
		},
		{
			name: "reset peer",
			end: func(manager *Manager, state *flow.State, _ *ParsedPacket) {
				if _, err := manager.ResetStream(state, &ParsedPacket{}); err != nil {
					t.Errorf("ResetStream error: %v", err)
				}
				if _, err := manager.ResetStream(state, &ParsedPacket{}); err != nil {
					t.Errorf("repeated ResetStream error: %v", err)
				}
			},
		},
		{
			name: "fail",
			end: func(manager *Manager, state *flow.State, packet *ParsedPacket) {
				manager.FailStream(state, packet, StreamDecoderPanic)
				manager.FailStream(state, packet, StreamDecoderPanic)
				if _, err := manager.OnFlowEnd(state); err != nil {
					t.Errorf("OnFlowEnd after FailStream: %v", err)
				}
			},
		},
		{
			name:      "framing error discard",
			parseFail: true,
			end: func(manager *Manager, state *flow.State, packet *ParsedPacket) {
				if result := manager.Inspect(state, packet); result.Err == nil {
					t.Error("Inspect after framing failure returned no error")
				}
				if _, err := manager.OnFlowEnd(state); err != nil {
					t.Errorf("OnFlowEnd after discard: %v", err)
				}
			},
		},
		{
			name: "flow end",
			end: func(manager *Manager, state *flow.State, _ *ParsedPacket) {
				if _, err := manager.OnFlowEnd(state); err != nil {
					t.Errorf("OnFlowEnd error: %v", err)
				}
				if _, err := manager.OnFlowEnd(state); err != nil {
					t.Errorf("repeated OnFlowEnd error: %v", err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoder := &statefulStreamDecoder{parseFail: test.parseFail}
			manager := NewManager(decoder)
			var want []streamEndCall
			for i, dir := range []StreamDir{ClientToServer, ServerToClient} {
				state := streamEndState(byte(i+1), i == 1)
				packet := legacyStreamPacket(dir)
				if test.name == "framing error discard" {
					packet = tcpSeg(10, 0x42)
					packet.Dir = dir
				}
				if test.name != "framing error discard" {
					manager.Inspect(state, packet)
				}
				test.end(manager, state, packet)
				want = append(want, streamEndCall{session: state.Key.Hash(), dir: dir})
			}
			assertStreamEndCalls(t, decoder, want...)
		})
	}
}

func TestStreamEnderNotCalledForUnparsedStream(t *testing.T) {
	decoder := &statefulStreamDecoder{}
	manager := NewManager(decoder)
	state := streamEndState(3, false)

	manager.FailStream(state, &ParsedPacket{Proto: "tcp", FailClosed: true}, StreamDecoderPanic)
	if _, err := manager.OnFlowEnd(state); err != nil {
		t.Fatal(err)
	}
	parsed, ended := decoder.calls()
	if len(parsed) != 0 || len(ended) != 0 {
		t.Fatalf("unparsed stream calls: ParseStream=%v StreamEnded=%v", parsed, ended)
	}
}

func TestStreamEnderReassemblyErrorDiscardsBothLegacyDirections(t *testing.T) {
	decoder := &statefulStreamDecoder{}
	manager := NewManager(decoder)
	var want []streamEndCall
	for i, dir := range []StreamDir{ClientToServer, ServerToClient} {
		state := streamEndState(byte(i+10), i == 1)
		first := tcpSeg(100, 0x42)
		first.Dir = dir
		manager.Inspect(state, first)
		overlap := tcpSeg(100, 0x43)
		overlap.Dir = dir
		if result := manager.Inspect(state, overlap); result.Err == nil {
			t.Errorf("direction %v overlap did not report an error", dir)
		}
		if _, err := manager.OnFlowEnd(state); err != nil {
			t.Errorf("OnFlowEnd after overlap discard: %v", err)
		}
		want = append(want, streamEndCall{session: state.Key.Hash(), dir: dir})
	}
	assertStreamEndCalls(t, decoder, want...)
}

func TestStreamEnderSYNReplacementStartsNewState(t *testing.T) {
	decoder := &statefulStreamDecoder{}
	manager := NewManager(decoder)
	state := streamEndState(4, false)

	manager.Inspect(state, &ParsedPacket{Proto: "tcp", TCPSyn: true, TCPSeqValid: true, TCPSeq: 100})
	manager.Inspect(state, tcpSeg(100, 0x42))
	_, ended := decoder.calls()
	if len(ended) != 0 {
		t.Fatalf("unexpected end before replacement: %+v", ended)
	}

	manager.Inspect(state, &ParsedPacket{Proto: "tcp", TCPSyn: true, TCPSeqValid: true, TCPSeq: 200})
	_, ended = decoder.calls()
	if len(ended) != 1 || ended[0] != (streamEndCall{session: state.Key.Hash(), dir: DirUnknown}) {
		t.Fatalf("SYN replacement calls = %+v", ended)
	}
	manager.Inspect(state, tcpSeg(200, 0x42))
	if _, err := manager.OnFlowEnd(state); err != nil {
		t.Fatal(err)
	}
	assertStreamEndCalls(t, decoder,
		streamEndCall{session: state.Key.Hash(), dir: DirUnknown},
		streamEndCall{session: state.Key.Hash(), dir: DirUnknown},
	)
	parsed, _ := decoder.calls()
	if len(parsed) != 2 {
		t.Fatalf("ParseStream calls after replacement = %d, want 2", len(parsed))
	}
}

func TestStreamEnderIdleExpiry(t *testing.T) {
	decoder := &statefulStreamDecoder{}
	manager := NewManager(decoder)
	manager.reassembler.idleTimeout = time.Second
	var stale []streamEndCall
	for i, dir := range []StreamDir{ClientToServer, ServerToClient} {
		state := streamEndState(byte(i+5), i == 1)
		manager.Inspect(state, legacyStreamPacket(dir))
		stale = append(stale, streamEndCall{session: state.Key.Hash(), dir: dir})
		manager.reassembler.mu.Lock()
		manager.reassembler.streams[state.Key.Hash()].lastUpdate = time.Now().Add(-2 * time.Second)
		manager.reassembler.mu.Unlock()
	}
	manager.reassembler.mu.Lock()
	manager.reassembler.lastSweep = time.Time{}
	manager.reassembler.mu.Unlock()

	trigger := streamEndState(7, false)
	manager.Inspect(trigger, legacyStreamPacket(ClientToServer))
	assertStreamEndCalls(t, decoder, stale...)
}

func TestStreamEnderIdleExpiryDropsFailClosedAssemblyOnce(t *testing.T) {
	decoder := &statefulStreamDecoder{}
	manager := NewManager(decoder)
	manager.reassembler.idleTimeout = time.Second
	state := streamEndState(8, false)
	manager.Inspect(state, &ParsedPacket{
		Proto:        "tcp",
		TCPSyn:       true,
		TCPSeqValid:  true,
		TCPHandshake: true,
		FailClosed:   true,
		TCPSeq:       100,
	})
	manager.Inspect(state, failClosedSeg(100, 0x42))
	key := state.Key.Hash()

	manager.reassembler.mu.Lock()
	manager.reassembler.streams[key].lastUpdate = time.Now().Add(-2 * time.Second)
	manager.reassembler.lastSweep = time.Time{}
	manager.reassembler.mu.Unlock()
	manager.Inspect(streamEndState(9, false), legacyStreamPacket(ClientToServer))

	want := streamEndCall{session: key, dir: DirUnknown}
	assertStreamEndCalls(t, decoder, want)
	lost := manager.Inspect(state, failClosedSeg(101, 0x43))
	if lost.Err == nil {
		t.Fatal("bytes after idle loss did not fail closed")
	}
	if _, err := manager.OnFlowEnd(state); err != nil {
		t.Fatal(err)
	}
	assertStreamEndCalls(t, decoder, want)
}

func TestStreamEnderConcurrentFlows(t *testing.T) {
	const flows = 32
	decoder := &statefulStreamDecoder{}
	manager := NewManager(decoder)
	var wg sync.WaitGroup
	wg.Add(flows)
	for i := range flows {
		go func(i int) {
			defer wg.Done()
			state := streamEndState(byte(i+1), i%2 == 1)
			dir := ClientToServer
			if i%2 == 1 {
				dir = ServerToClient
			}
			manager.Inspect(state, legacyStreamPacket(dir))
			if _, err := manager.OnFlowEnd(state); err != nil {
				t.Errorf("OnFlowEnd: %v", err)
			}
		}(i)
	}
	wg.Wait()

	parsed, ended := decoder.calls()
	if len(parsed) != flows || len(ended) != flows {
		t.Fatalf("concurrent calls: parsed=%d ended=%d, want %d each", len(parsed), len(ended), flows)
	}
	for _, call := range parsed {
		matches := 0
		for _, end := range ended {
			if end == call {
				matches++
			}
		}
		if matches != 1 {
			t.Errorf("parsed stream %+v has %d end notifications", call, matches)
		}
	}
}
