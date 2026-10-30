// SPDX-License-Identifier: Apache-2.0
//go:build linux

package capture

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
)

// Run with CONTAIND_NETNS_KERNEL_TEST=1 in an isolated Linux network namespace
// as root with CAP_NET_ADMIN and nft. It intentionally never uses queue bypass.
func TestKernelNFQueueRepeatMarkResumesFirewall(t *testing.T) {
	requireKernel(t)
	const queue = 4714
	const observed uint32 = 0x04000000
	var seen atomic.Int32
	mgr, err := NewManager(Config{Mode: "nfqueue", QueueID: queue})
	if err != nil {
		t.Fatal(err)
	}
	if err = mgr.Start(context.Background(), func(p Packet) Decision {
		if seen.Add(1) > 2 {
			return Decision{Action: Drop}
		} // bound a broken requeue loop
		if p.Mark != 0x000000ab {
			t.Errorf("original mark %#x", p.Mark)
		}
		return Decision{Action: Repeat, Mark: p.Mark&0xf0ffffff | observed}
	}); err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()
	for _, allow := range []bool{false, true} {
		t.Run(fmt.Sprint("accept=", allow), func(t *testing.T) {
			ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			port := ln.LocalAddr().(*net.UDPAddr).Port
			final := "drop"
			if allow {
				final = "accept"
			}
			nft(t, fmt.Sprintf(`table inet containd_repeat_test {
 chain out {
  type filter hook output priority 0; policy accept;
  udp dport %d meta mark & 0x04000000 == 0 meta mark set 0x000000ab queue num %d
  udp dport %d meta mark & 0x04000000 == 0 queue num %d
  udp dport %d meta mark != 0x040000ab drop
  udp dport %d %s
 }
}`, port, queue, port, queue, port, port, final))
			defer func() {
				if out, err := exec.Command("nft", "delete", "table", "inet", "containd_repeat_test").CombinedOutput(); err != nil {
					t.Errorf("cleanup: %v %s", err, out)
				}
			}()
			conn, err := net.DialUDP("udp4", nil, ln.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			before := seen.Load()
			if _, err = conn.Write([]byte("repeat")); err != nil {
				t.Fatal(err)
			}
			if err = ln.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 20)
			n, err := ln.Read(b)
			if allow && (err != nil || string(b[:n]) != "repeat") {
				t.Fatalf("receiver n=%d err=%v", n, err)
			}
			if !allow && err == nil {
				t.Fatal("later L4 drop was bypassed")
			}
			if got := seen.Load() - before; got != 1 {
				t.Fatalf("queued %d times, want exactly once", got)
			}
		})
	}
}
