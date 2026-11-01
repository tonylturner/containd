// SPDX-License-Identifier: Apache-2.0
//go:build linux

package capture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"golang.org/x/sys/unix"
)

func spikeKernel(t *testing.T) {
	t.Helper()
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" {
		t.Skip("requires opt-in disposable kernel container")
	}
	requireKernel(t)
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("kernel %s", strings.TrimSpace(string(out)))
}

func spikeUDP(t *testing.T) (*net.UDPConn, *net.UDPConn, int) {
	t.Helper()
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	conn, err := net.DialUDP("udp4", nil, ln.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return ln, conn, ln.LocalAddr().(*net.UDPAddr).Port
}

func spikeSend(t *testing.T, conn *net.UDPConn, msg string) {
	t.Helper()
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
}

func spikeReceive(t *testing.T, ln *net.UDPConn, want string) {
	t.Helper()
	if err := ln.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	n, err := ln.Read(buf)
	if want == "" {
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("want no delivery, got %q err=%v", buf[:n], err)
		}
	} else if err != nil || string(buf[:n]) != want {
		t.Fatalf("want %q, got %q err=%v", want, buf[:n], err)
	}
}

func spikeNext[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for queue event")
		var zero T
		return zero
	}
}

// Deleting any base hook flushes queued skbs. The verdict send itself succeeds;
// the kernel's ENOENT arrives on the go-nfqueue receive/error callback instead.
// That is token loss, not source failure: a replacement table must keep using
// the same bound queue generation.
func TestKernelApplyDropsHeldAndKeepsQueueUsable(t *testing.T) {
	spikeKernel(t)
	const queue = 4721
	ln, conn, port := spikeUDP(t)
	held := make(chan Token, 4)
	sources := make(chan SourceEvent, 8)
	errs := make(chan error, 8)
	mgr, err := NewManager(Config{Mode: "nfqueue", QueueID: queue,
		OnSource: func(ev SourceEvent) { sources <- ev },
		OnError:  func(err error) { errs <- err },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Start(context.Background(), func(p Packet) Decision {
		if string(p.Payload) == "held" {
			held <- p.Token
			return Decision{Action: Hold}
		}
		return Decision{Action: Accept}
	}); err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()
	first := spikeNext(t, sources)
	install := func() {
		nft(t, fmt.Sprintf(`table inet spike_flush {
 chain out { type filter hook output priority 0; policy accept;
 udp dport %d queue num %d
 }
}`, port, queue))
	}
	install()
	t.Cleanup(func() { nft(t, "delete table inet spike_flush") })
	spikeSend(t, conn, "held")
	tok := spikeNext(t, held)
	nft(t, "delete table inet spike_flush")
	// Replace the table before sending the stale verdict, as apply does.
	install()
	spikeReceive(t, ln, "")
	submitErr := mgr.Settler().Settle(Resolution{Token: tok, Verdict: VerdictAccept})[0]
	t.Logf("late SetVerdict/Settle returned %v", submitErr)
	if submitErr != nil {
		t.Fatalf("expected successful sendmsg, got %v", submitErr)
	}
	receiveErr := spikeNext(t, errs)
	t.Logf("go-nfqueue errFn -> OnError: %T: %v", receiveErr, receiveErr)
	if !errors.Is(receiveErr, unix.ENOENT) {
		t.Fatalf("want asynchronous ENOENT, got %v", receiveErr)
	}
	if !first.Ready {
		t.Fatal("queue was not ready")
	}
	spikeReceive(t, ln, "")
	spikeSend(t, conn, "fresh")
	spikeReceive(t, ln, "fresh")
	select {
	case ev := <-sources:
		t.Fatalf("flushed token changed source generation: %+v", ev)
	default:
	}
}

func spikeCounter(table, name string) (uint64, error) {
	out, err := exec.Command("nft", "-j", "list", "counter", "inet", table, name).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("counter: %w: %s", err, out)
	}
	var doc struct {
		Nftables []struct {
			Counter *struct{ Packets uint64 } `json:"counter"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return 0, err
	}
	for _, item := range doc.Nftables {
		if item.Counter != nil {
			return item.Counter.Packets, nil
		}
	}
	return 0, fmt.Errorf("counter %s missing", name)
}

// Use the library directly so the observation is immediately after SetVerdict,
// not after a Manager completion goroutine or UDP delivery notification.
// The counter read is observational evidence at return, not a scheduling proof.
func TestKernelSpikeS2RepeatCounterVisibleAtVerdictReturn(t *testing.T) {
	spikeKernel(t)
	const queue = 4722
	ln, conn, port := spikeUDP(t)
	nft(t, fmt.Sprintf(`table inet spike_sync {
 counter after { }
 chain out { type filter hook output priority 0; policy accept;
 udp dport %d meta mark & 0x04000000 == 0 queue num %d
 udp dport %d counter name after
 }
}`, port, queue, port))
	t.Cleanup(func() { nft(t, "delete table inet spike_sync") })
	nf, err := nfqueue.Open(&nfqueue.Config{NfQueue: queue, MaxPacketLen: 65535, MaxQueueLen: 32, Copymode: nfqueue.NfQnlCopyPacket})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nf.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan error, 4)
	if err := nf.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			results <- fmt.Errorf("missing packet ID")
			return 1
		}
		err := nf.SetVerdictWithOption(*a.PacketID, nfqueue.NfRepeat, nfqueue.WithMark(0x04000000))
		if err == nil {
			var count uint64
			count, err = spikeCounter("spike_sync", "after")
			if err == nil && count != 1 {
				err = fmt.Errorf("immediately after SetVerdict: counter=%d, want 1", count)
			}
		}
		results <- err
		return 0
	}, func(err error) int { results <- err; return 1 }); err != nil {
		t.Fatal(err)
	}
	spikeSend(t, conn, "synchronous")
	if err := spikeNext(t, results); err != nil {
		t.Fatal(err)
	}
	spikeReceive(t, ln, "synchronous")
	t.Log("post-queue counter = 1 immediately after SetVerdict returned")
}

func TestKernelSpikeS3RepeatOnlyQueueingChainAndMarkReplacement(t *testing.T) {
	spikeKernel(t)
	const queue = 4723
	ln, conn, port := spikeUDP(t)
	nft(t, fmt.Sprintf(`table inet spike_repeat {
 counter earlier { }
 counter queue_chain { }
 counter replacement { }
 chain early { type filter hook output priority -10; policy accept;
 udp dport %d counter name earlier meta mark set 0xab
 }
 chain out { type filter hook output priority 0; policy accept;
 udp dport %d counter name queue_chain
 udp dport %d meta mark & 0x04000000 == 0 queue num %d
 udp dport %d meta mark 0x04000000 counter name replacement accept
 udp dport %d drop
 }
}`, port, port, port, queue, port, port))
	t.Cleanup(func() { nft(t, "delete table inet spike_repeat") })
	marks := make(chan uint32, 8)
	var seen atomic.Int32
	mgr, err := NewManager(Config{Mode: "nfqueue", QueueID: queue})
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Start(context.Background(), func(p Packet) Decision {
		marks <- p.Mark
		// Bound a broken reinjection loop without concealing its counters.
		if seen.Add(1) > 2 || p.Mark != 0xab {
			return Decision{Action: Drop}
		}
		return Decision{Action: Repeat, Mark: 0x04000000}
	}); err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()
	spikeSend(t, conn, "replace")
	if got := spikeNext(t, marks); got != 0xab {
		t.Fatalf("queued mark %#x", got)
	}
	spikeReceive(t, ln, "replace")
	for name, want := range map[string]uint64{"earlier": 1, "queue_chain": 2, "replacement": 1} {
		count, err := spikeCounter("spike_repeat", name)
		if err != nil || count != want {
			t.Fatalf("%s=%d want %d: %v", name, count, want, err)
		}
		t.Logf("%s=%d", name, count)
	}
}
