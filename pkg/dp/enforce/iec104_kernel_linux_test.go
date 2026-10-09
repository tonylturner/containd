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
// (it flushes the ruleset of its network namespace), so it skips otherwise
// unless CONTAIND_KERNEL_TESTS=1. Run in a throwaway container:
//
//	GOOS=linux CGO_ENABLED=0 go test -c -o build/enforce.test ./pkg/dp/enforce
//	docker run --rm --cap-add NET_ADMIN --user 0 -e CONTAIND_KERNEL_TESTS=1 \
//	  -v "$PWD/build:/w" --entrypoint /w/enforce.test containd/containd:dev -test.run Kernel -test.v
func TestKernelIEC104SteeringLoads(t *testing.T) {
	if os.Getenv("CONTAIND_KERNEL_TESTS") != "1" {
		t.Skip("set CONTAIND_KERNEL_TESTS=1 in a throwaway network namespace: the test flushes the nft ruleset")
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
	out, err := exec.Command("nft", "list", "chain", "inet", "containd", "forward").CombinedOutput()
	if err != nil {
		t.Fatalf("list: %v: %s", err, out)
	}
	listed := string(out)
	for _, want := range []string{
		"tcp dport 2404 ip saddr 10.60.60.0/24 ip daddr 10.70.0.5 meta mark set meta mark & 0xf1ffffff | 0x01000000 queue to 100",
		"tcp sport 2404 ip saddr 10.70.0.5 ip daddr 10.60.60.0/24 meta mark set meta mark & 0xf1ffffff | 0x01000000 queue to 100",
	} {
		if !strings.Contains(listed, want) {
			t.Fatalf("kernel ruleset lacks %q:\n%s", want, listed)
		}
	}
	if strings.Index(listed, "tcp sport 2404") > strings.Index(listed, "ct state { established, related } accept") {
		t.Fatalf("steering must precede the established accept:\n%s", listed)
	}
}
