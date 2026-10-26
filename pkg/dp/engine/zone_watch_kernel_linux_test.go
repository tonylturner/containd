// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

//go:build linux

package engine

import (
	"context"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// TestZoneWatchKernelAddressChange runs the engine's zone cache against
// the kernel: a running engine resolves a zone interface's networks once,
// and after the interface's address changes it resolves the new network
// without a reconfiguration. It adds a dummy interface to this namespace,
// so it runs only when CONTAIND_NETNS_KERNEL_TEST=1 in a disposable
// privileged Linux container with iproute2 (see
// first_command_kernel_linux_test.go).
func TestZoneWatchKernelAddressChange(t *testing.T) {
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires CONTAIND_NETNS_KERNEL_TEST=1 in a disposable privileged Linux container with iproute2")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}
	ip("link", "add", "zw0", "type", "dummy")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "zw0").Run() })
	ip("addr", "add", "198.18.70.1/24", "dev", "zw0")
	ip("link", "set", "zw0", "up")

	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	e.zones.addrsFor = func(name string) ([]net.Addr, error) {
		reads++ // lookups run on this goroutine only
		return interfaceAddrs(name)
	}
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		fresh, err := New(Config{Events: e.Events()})
		if err == nil {
			err = e.Reconfigure(fresh)
		}
		if err != nil {
			t.Errorf("stop engine: %v", err)
		}
	})
	waitFor(t, "the zone cache subscription", func() bool { return e.zones.watched.Load() })
	// Let the notifications of the interface setup arrive before counting.
	time.Sleep(200 * time.Millisecond)
	snap := &rules.Snapshot{ZoneIfaces: map[string][]string{"plant": {"zw0"}}}
	zoneOf := func(addr string) string {
		src, _ := e.zones.resolve(snap, net.ParseIP(addr), nil)
		return src
	}
	if got := zoneOf("198.18.70.9"); got != "plant" {
		t.Fatalf("zone before the change = %q, want plant", got)
	}
	before := reads
	for range 10 {
		zoneOf("198.18.70.9")
	}
	if reads != before {
		t.Fatalf("%d interface reads for 10 lookups without a change, want none", reads-before)
	}

	ip("addr", "del", "198.18.70.1/24", "dev", "zw0")
	ip("addr", "add", "198.18.71.1/24", "dev", "zw0")
	waitFor(t, "the new network's zone", func() bool { return zoneOf("198.18.71.9") == "plant" })
	if got := zoneOf("198.18.70.9"); got != "" {
		t.Fatalf("removed network still resolves to zone %q", got)
	}

	// After Reconfigure stops the run, nothing watches and every lookup
	// reads the interfaces.
	fresh, err := New(Config{Events: e.Events()})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Reconfigure(fresh); err != nil {
		t.Fatal(err)
	}
	if e.zones.watched.Load() {
		t.Fatal("the zone cache is still subscribed after the run stopped")
	}
	before = reads
	zoneOf("198.18.71.9")
	zoneOf("198.18.71.9")
	if reads-before != 2 {
		t.Fatalf("%d interface reads for 2 unwatched lookups, want 2", reads-before)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
