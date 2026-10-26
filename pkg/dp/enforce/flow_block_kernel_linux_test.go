// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Run only inside a disposable network namespace: compilation flushes nftables.
func TestKernelFlowBlockProtocolKeys(t *testing.T) {
	if os.Getenv("CONTAIND_KERNEL_TESTS") != "1" {
		t.Skip("requires CONTAIND_KERNEL_TESTS=1 in an isolated Linux container with NET_ADMIN and nft")
	}
	if _, err := exec.LookPath("nft"); err != nil || os.Geteuid() != 0 {
		t.Fatalf("kernel test needs root and nft: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	text, err := NewCompiler().CompileFirewall(&rules.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewNftApplier().Apply(ctx, text); err != nil {
		t.Fatal(err)
	}
	u := NewNftUpdater("containd")
	for _, proto := range []string{"tcp", "udp"} {
		if err := u.BlockFlowTemp(ctx, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), proto, "502", time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	out, err := exec.CommandContext(ctx, "nft", "list", "set", "inet", "containd", "block_flows").CombinedOutput()
	if err != nil {
		t.Fatalf("list block_flows: %v: %s", err, out)
	}
	for _, proto := range []string{"tcp", "udp"} {
		if !strings.Contains(string(out), "10.0.0.1 . 10.0.0.2 . "+proto+" . 502") {
			t.Fatalf("kernel lost %s key:\n%s", proto, out)
		}
	}
}
