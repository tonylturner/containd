// SPDX-License-Identifier: Apache-2.0
//go:build linux

package conntrack_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
)

func TestKernelSpikeS4MaskedConntrackMarkSweep(t *testing.T) {
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" {
		t.Skip("requires opt-in disposable kernel container")
	}
	// ClearMark deliberately scans the whole namespace. Other kernel tests
	// leave admitted owned-forward entries (mark & 3 == 3), so sockets and
	// nft rules alone do not isolate the expected update count.
	if os.Getenv("CONTAIND_MARK_SWEEP_PEER") != "1" {
		runIsolatedMarkSweep(t)
		return
	}
	ctx := context.Background()
	nft := func(script string) {
		t.Helper()
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft: %v: %s", err, out)
		}
	}
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.LocalAddr().(*net.UDPAddr).Port
	c, err := net.DialUDP("udp4", nil, ln.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	other, err := net.DialUDP("udp4", nil, ln.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	sport, otherSport := c.LocalAddr().(*net.UDPAddr).Port, other.LocalAddr().(*net.UDPAddr).Port
	nft(fmt.Sprintf(`table inet spike_mark {
 chain out { type filter hook output priority 0; policy accept;
 udp sport %d udp dport %d ct mark set 0xa532ff03
 udp sport %d udp dport %d ct mark set 0xa532ff02
 }
}`, sport, port, otherSport, port))
	t.Cleanup(func() { nft("delete table inet spike_mark") })
	for _, conn := range []*net.UDPConn{c, other} {
		if _, err := conn.Write([]byte("mark")); err != nil {
			t.Fatal(err)
		}
	}
	check := func(want string) {
		t.Helper()
		entries, err := conntrack.List(ctx, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, e := range entries {
			if e.Proto != "udp" || e.Src != "127.0.0.1" || e.Dport != fmt.Sprint(port) {
				continue
			}
			expected := fmt.Sprint(uint32(0xa532ff02))
			if e.Sport == fmt.Sprint(sport) {
				expected = want
			} else if e.Sport != fmt.Sprint(otherSport) {
				continue
			}
			if e.Mark != expected {
				t.Fatalf("sport %s mark=%s want %s", e.Sport, e.Mark, expected)
			}
			found++
		}
		if found != 2 {
			t.Fatalf("found %d fixture entries, want 2", found)
		}
	}
	check(fmt.Sprint(uint32(0xa532ff03)))
	n, err := conntrack.ClearMark(ctx, 3, 3, 2)
	if err != nil || n != 1 {
		t.Fatalf("sweep updated %d entries: %v", n, err)
	}
	check(fmt.Sprint(uint32(0xa532ff01)))
	if n, err := conntrack.ClearMark(ctx, 3, 3, 2); err != nil || n != 0 {
		t.Fatalf("second sweep updated %d entries: %v", n, err)
	}
	t.Log("CTA_MARK=0 CTA_MARK_MASK=2 cleared only bit 1; unrelated bits and opposite-parity entry unchanged")
}

func runIsolatedMarkSweep(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ns := fmt.Sprintf("mark-sweep-%d", os.Getpid())
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
	}
	run("ip", "netns", "add", ns)
	t.Cleanup(func() {
		if out, err := exec.Command("ip", "netns", "del", ns).CombinedOutput(); err != nil {
			t.Errorf("delete mark sweep namespace: %v: %s", err, out)
		}
	})
	run("ip", "-n", ns, "link", "set", "lo", "up")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns, binary,
		"-test.run=^TestKernelSpikeS4MaskedConntrackMarkSweep$", "-test.v")
	cmd.Env = append(os.Environ(), "CONTAIND_MARK_SWEEP_PEER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated mark sweep: %v: %s", err, out)
	}
	t.Logf("isolated mark sweep: %s", out)
}
