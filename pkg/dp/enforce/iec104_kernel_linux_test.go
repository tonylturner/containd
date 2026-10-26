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
// (it replaces containd's tables in its network namespace), so it skips otherwise
// unless CONTAIND_KERNEL_TESTS=1. Run in a throwaway container:
//
//	GOOS=linux CGO_ENABLED=0 go test -c -o build/enforce.test ./pkg/dp/enforce
//	docker run --rm --cap-add NET_ADMIN --user 0 -e CONTAIND_KERNEL_TESTS=1 \
//	  -v "$PWD/build:/w" --entrypoint /w/enforce.test containd/containd:dev -test.run Kernel -test.v
func TestKernelIEC104SteeringLoads(t *testing.T) {
	if os.Getenv("CONTAIND_KERNEL_TESTS") != "1" {
		t.Skip("set CONTAIND_KERNEL_TESTS=1 in a throwaway network namespace: the test replaces containd's nft tables")
	}
	if _, err := exec.LookPath("nft"); err != nil || os.Geteuid() != 0 {
		t.Fatalf("CONTAIND_KERNEL_TESTS=1 needs root and nft (lookup err %v)", err)
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
	listed := nftList(t, "forward")
	counted := counterStmt("a-iec-allow") + " jump iec104_envelope"
	for _, want := range []string{
		"tcp dport 2404 ip saddr 10.60.60.0/24 ip daddr 10.70.0.5 " + counted,
		"tcp sport 2404 ip saddr 10.70.0.5 ip daddr 10.60.60.0/24 " + counted,
	} {
		if !strings.Contains(listed, want) {
			t.Fatalf("kernel ruleset lacks %q:\n%s", want, listed)
		}
	}
	if strings.Index(listed, "tcp sport 2404") > strings.Index(listed, "ct state { established, related } accept") {
		t.Fatalf("steering must precede the established accept:\n%s", listed)
	}
	// Compiled closed, the envelope drops; the switch opens and closes it
	// in place without touching the forward chain.
	const queued = "meta mark set meta mark & 0xf1ffffff | 0x01000000 queue to 100"
	if env := nftList(t, IEC104EnvelopeChain); !strings.Contains(env, "drop") || strings.Contains(env, "queue") {
		t.Fatalf("closed envelope chain:\n%s", env)
	}
	for _, open := range []bool{true, false, true} {
		if err := NewNftApplier().Apply(context.Background(), c.IEC104EnvelopeSwitch(open)); err != nil {
			t.Fatalf("switch open=%v: %v", open, err)
		}
		env := nftList(t, IEC104EnvelopeChain)
		if open != strings.Contains(env, queued) || open == strings.Contains(env, "drop") {
			t.Fatalf("envelope chain after switch open=%v:\n%s", open, env)
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
