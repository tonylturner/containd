// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package capture

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Kernel tests need root with CAP_NET_ADMIN and the nft binary. They skip
// otherwise, unless CONTAIND_NETNS_KERNEL_TEST=1 demands them. Run them with:
//
//	GOOS=linux CGO_ENABLED=0 go test -c -o build/capture.test ./pkg/dp/capture
//	docker run --rm --cap-add NET_ADMIN --user 0 -e CONTAIND_NETNS_KERNEL_TEST=1 \
//	  -v "$PWD/build:/w" --entrypoint /w/capture.test containd/containd:dev \
//	  -test.run Kernel -test.v
func requireKernel(t *testing.T) {
	t.Helper()
	demanded := os.Getenv("CONTAIND_NETNS_KERNEL_TEST") == "1"
	missing := ""
	if os.Geteuid() != 0 {
		missing = "root"
	} else if _, err := exec.LookPath("nft"); err != nil {
		missing = "the nft binary"
	}
	if missing == "" {
		return
	}
	if demanded {
		t.Fatalf("CONTAIND_NETNS_KERNEL_TEST=1 but %s is unavailable", missing)
	}
	t.Skipf("kernel test needs %s", missing)
}

func nft(t *testing.T, ruleset string) {
	t.Helper()
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft: %v: %s", err, out)
	}
}

// queueBound reports whether the kernel lists queue as bound to a socket.
func queueBound(t *testing.T, queue int) bool {
	t.Helper()
	data, err := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	if errors.Is(err, os.ErrNotExist) {
		return false // module loaded on first bind; no file means no queue
	}
	if err != nil {
		t.Fatalf("read nfnetlink_queue: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == strconv.Itoa(queue) {
			return true
		}
	}
	return false
}

type kernelRecorder struct {
	mu       sync.Mutex
	verdicts map[Token][]error
	kinds    map[Token][]Verdict
	sources  []SourceEvent
	order    []string
	held     chan Token
	seen     []string
	badMarks []uint32 // packets without the skb mark the steering rule set
}

func newKernelRecorder() *kernelRecorder {
	return &kernelRecorder{verdicts: map[Token][]error{}, kinds: map[Token][]Verdict{}, held: make(chan Token, 16)}
}

func (r *kernelRecorder) onVerdict(tok Token, v Verdict, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verdicts[tok] = append(r.verdicts[tok], err)
	r.kinds[tok] = append(r.kinds[tok], v)
	r.order = append(r.order, "verdict "+tok.String())
}

func (r *kernelRecorder) onSource(ev SourceEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sources = append(r.sources, ev)
	r.order = append(r.order, "source")
}

// handler decides by payload prefix: accept, drop, or hold (the token is
// published on r.held).
func (r *kernelRecorder) handler(p Packet) Decision {
	msg := string(p.Payload)
	r.mu.Lock()
	r.seen = append(r.seen, msg)
	if !p.HasMark || p.Mark != 0x01000000 {
		r.badMarks = append(r.badMarks, p.Mark)
	}
	r.mu.Unlock()
	switch {
	case strings.HasPrefix(msg, "drop"):
		return Decision{Action: Drop}
	case strings.HasPrefix(msg, "hold"):
		r.held <- p.Token
		return Decision{Action: Hold}
	default:
		return Decision{Action: Accept}
	}
}

func (r *kernelRecorder) sawPayload(msg string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.seen {
		if s == msg {
			return true
		}
	}
	return false
}

func TestKernelNFQueueInlineVerdictsAndCloseDropsHeld(t *testing.T) {
	requireKernel(t)
	const queue, port = 4711, 40404
	nft(t, `table inet containd_kernel_test {
  chain out {
    type filter hook output priority 0; policy accept;
    udp dport `+strconv.Itoa(port)+` meta mark set meta mark and 0xf0ffffff or 0x01000000 queue num `+strconv.Itoa(queue)+`
  }
}`)
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "containd_kernel_test").Run() })

	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	received := make(chan string, 32)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := ln.Read(buf)
			if err != nil {
				return
			}
			received <- string(buf[:n])
		}
	}()
	conn, err := net.DialUDP("udp4", nil, ln.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	send := func(msg string) {
		t.Helper()
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatalf("send %q: %v", msg, err)
		}
	}
	expect := func(msg string) {
		t.Helper()
		select {
		case got := <-received:
			if got != msg {
				t.Fatalf("received %q, want %q", got, msg)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%q was not delivered", msg)
		}
	}
	expectNothing := func(what string) {
		t.Helper()
		select {
		case got := <-received:
			t.Fatalf("%s: received %q, want nothing", what, got)
		case <-time.After(300 * time.Millisecond):
		}
	}
	nextHeld := func(r *kernelRecorder) Token {
		t.Helper()
		select {
		case tok := <-r.held:
			return tok
		case <-time.After(2 * time.Second):
			t.Fatal("handler did not hold a packet")
			return Token{}
		}
	}

	r := newKernelRecorder()
	mgr, err := NewManager(Config{Mode: "nfqueue", QueueID: queue, OnVerdict: r.onVerdict, OnSource: r.onSource})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.Start(context.Background(), r.handler); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !queueBound(t, queue) {
		t.Fatal("Start returned before the queue was bound")
	}

	send("accept-1")
	expect("accept-1")

	send("drop-1")
	expectNothing("current-packet drop")

	send("hold-accept")
	heldAccept := nextHeld(r)
	expectNothing("held packet")
	if errs := mgr.Settler().Settle(Resolution{Token: heldAccept, Verdict: VerdictAccept}); errs[0] != nil {
		t.Fatalf("Settle accept: %v", errs[0])
	}
	expect("hold-accept")

	send("hold-drop")
	heldDrop := nextHeld(r)
	if errs := mgr.Settler().Settle(Resolution{Token: heldDrop, Verdict: VerdictDrop}); errs[0] != nil {
		t.Fatalf("Settle drop: %v", errs[0])
	}
	expectNothing("deferred drop")

	send("hold-close")
	heldAtClose := nextHeld(r)
	gen := heldAtClose.Generation()
	mgr.Stop()
	if queueBound(t, queue) {
		t.Fatal("queue still bound after Stop")
	}
	expectNothing("packet held at queue close")

	r.mu.Lock()
	if errs := r.verdicts[heldAtClose]; len(errs) != 1 || !errors.Is(errs[0], ErrQueueClosed) || r.kinds[heldAtClose][0] != VerdictDrop {
		t.Fatalf("held-at-close completions = %v %v, want one (Drop, ErrQueueClosed)", r.kinds[heldAtClose], errs)
	}
	for _, tok := range []Token{heldAccept, heldDrop} {
		if errs := r.verdicts[tok]; len(errs) != 1 || errs[0] != nil {
			t.Fatalf("token %v completions = %v, want one success", tok, errs)
		}
	}
	if len(r.sources) != 2 || !r.sources[0].Ready || r.sources[0].Generation != gen ||
		r.sources[1].Ready || r.sources[1].Generation != gen || !errors.Is(r.sources[1].Err, ErrQueueClosed) {
		t.Fatalf("source events = %+v, want ready then down for generation %d", r.sources, gen)
	}
	if last := r.order[len(r.order)-1]; last != "source" {
		t.Fatalf("down event was not last: %v", r.order)
	}
	if len(r.badMarks) != 0 {
		t.Fatalf("packets without the steering mark: %#x", r.badMarks)
	}
	r.mu.Unlock()

	// No queue bypass: with no listener bound, new packets are dropped.
	send("after-close")
	expectNothing("packet queued while unbound")

	// A new binding never sees the old packets: the kernel dropped them.
	r2 := newKernelRecorder()
	mgr2, err := NewManager(Config{Mode: "nfqueue", QueueID: queue, OnVerdict: r2.onVerdict, OnSource: r2.onSource})
	if err != nil {
		t.Fatalf("NewManager 2: %v", err)
	}
	if err := mgr2.Start(context.Background(), r2.handler); err != nil {
		t.Fatalf("Start 2: %v", err)
	}
	defer mgr2.Stop()
	send("accept-2")
	expect("accept-2")
	expectNothing("old packets after rebind")
	if r2.sawPayload("hold-close") || r2.sawPayload("after-close") {
		t.Fatal("packets from the closed queue reached the new binding")
	}
	r2.mu.Lock()
	defer r2.mu.Unlock()
	if len(r2.sources) != 1 || !r2.sources[0].Ready || r2.sources[0].Generation <= gen {
		t.Fatalf("second manager sources = %+v, want a newer ready generation", r2.sources)
	}
}

// Packets capture cannot decode reach the handler with Invalid set; capture
// accepts nothing on its own.
func TestKernelNFQueueDeliversUndecodablePackets(t *testing.T) {
	requireKernel(t)
	const queue = 4712
	nft(t, `table inet containd_kernel_invalid {
  chain out {
    type filter hook output priority 0; policy accept;
    ip daddr 127.0.0.1 ip protocol icmp queue num `+strconv.Itoa(queue)+`
  }
}`)
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "containd_kernel_invalid").Run() })

	invalid := make(chan Packet, 4)
	mgr, err := NewManager(Config{Mode: "nfqueue", QueueID: queue})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.Start(context.Background(), func(p Packet) Decision {
		invalid <- p
		return Decision{Action: Drop}
	}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.Stop()

	conn, err := net.Dial("ip4:icmp", "127.0.0.1")
	if err != nil {
		t.Fatalf("icmp socket: %v", err)
	}
	defer conn.Close()
	echo := []byte{8, 0, 0xf7, 0xfe, 0, 1, 0, 0} // echo request, id 1 seq 0, checksum
	if _, err := conn.Write(echo); err != nil {
		t.Fatalf("send icmp: %v", err)
	}
	select {
	case p := <-invalid:
		if p.Invalid != InvalidProtocol || !p.Token.Inline() || p.SrcIP.String() != "127.0.0.1" {
			t.Fatalf("handler got Invalid=%q token=%v src=%v, want protocol/inline/127.0.0.1", p.Invalid, p.Token, p.SrcIP)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("undecodable packet never reached the handler")
	}
}
