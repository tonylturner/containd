// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package enforce

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestKernelIEC104SteeringLoads applies a compiled ruleset with IEC104
// envelope steering to the kernel. It needs root, CAP_NET_ADMIN and nft
// (it replaces containd's tables in its network namespace), so it runs only
// when CONTAIND_NETNS_KERNEL_TEST=1 in a disposable privileged container,
// as the other kernel tests of this package (see netns_kernel_linux_test.go).
func TestKernelIEC104SteeringLoads(t *testing.T) {
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires CONTAIND_NETNS_KERNEL_TEST=1 in a disposable privileged Linux container with nft: the test replaces containd's nft tables")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Fatalf("kernel test needs nft: %v", err)
	}
	c := NewCompiler()
	c.QueueID = 100
	ruleset, err := c.CompileFirewall(iecSnapshot())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if err := NewNftApplier().Apply(context.Background(), ruleset); err != nil {
		t.Fatalf("apply: %v\n%s", err, ruleset)
	}
	t.Cleanup(func() {
		if err := NewNftApplier().Apply(context.Background(), c.DeleteTables()); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	listed := nftList(t, "forward")
	for _, want := range []string{
		`ct direction original iifname "eth1" oifname "eth2" meta l4proto tcp ct reply proto-src 2404`,
		`ct direction reply iifname "eth2" oifname "eth1" meta l4proto tcp ct reply proto-src 2404`,
	} {
		if !strings.Contains(listed, want) {
			t.Fatalf("kernel ruleset lacks %q:\n%s", want, listed)
		}
	}
	if strings.Index(listed, "jump iec104_envelope") > strings.Index(listed, "goto admit_clean") {
		t.Fatal("steering follows parity")
	}
	// Compiled closed, the envelope drops; the switch opens and closes it
	// in place without touching the forward chain. Open, it queues with
	// EnvelopeMark, and HandshakeMark too for a connection conntrack has
	// not seen complete its handshake.
	queued := []string{
		"ct status assured meta mark set meta mark & 0xe9ffffff | 0x09000000 queue to 100",
		"ct state != { invalid, untracked } meta mark set meta mark & 0xebffffff | 0x0b000000 queue to 100",
		"meta mark set meta mark & 0xe9ffffff | 0x09000000 queue to 100",
	}
	if env := nftList(t, IEC104EnvelopeChain); !strings.Contains(env, "drop") || strings.Contains(env, "queue") {
		t.Fatalf("closed envelope chain:\n%s", env)
	}
	for _, open := range []bool{true, false, true} {
		if err := NewNftApplier().Apply(context.Background(), c.IEC104EnvelopeSwitch(open)); err != nil {
			t.Fatalf("switch open=%v: %v", open, err)
		}
		env := nftList(t, IEC104EnvelopeChain)
		if open == strings.Contains(env, "drop") || open != strings.Contains(env, "queue") {
			t.Fatalf("envelope chain after switch open=%v:\n%s", open, env)
		}
		if open && !strings.Contains(env, strings.Join(queued, "\n\t\t")+"\n") {
			t.Fatalf("open envelope chain, want rules %q:\n%s", queued, env)
		}
		if got := nftList(t, "forward"); got != listed {
			t.Fatalf("the switch changed the forward chain:\n%s", got)
		}
	}
}

func nftList(t *testing.T, chain string) string {
	t.Helper()
	out, err := exec.Command("nft", "list", "chain", "inet", PolicyTable(""), chain).CombinedOutput()
	if err != nil {
		t.Fatalf("list %s: %v: %s", chain, err, out)
	}
	return string(out)
}
