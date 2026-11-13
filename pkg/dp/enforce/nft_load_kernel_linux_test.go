// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// TestKernelNFTLoadsGoldens checks every golden ruleset, whole scripts
// with both tables, against the nft and kernel of this container. Run it
// with the other kernel tests (see newNetnsLab) in each image whose nft
// containd supports.
func TestKernelNFTLoadsGoldens(t *testing.T) {
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires CONTAIND_NETNS_KERNEL_TEST=1 in a disposable privileged Linux container with nft")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cases := map[string]func() (*Compiler, *rules.Snapshot){
		"actions": func() (*Compiler, *rules.Snapshot) {
			c := NewCompiler()
			c.QueueID, c.NFLogGroup = 100, 7
			return c, actionsSnapshot()
		},
		"iec104": func() (*Compiler, *rules.Snapshot) {
			c := NewCompiler()
			c.QueueID, c.NFLogGroup, c.IEC104EnvelopeOpen = 100, 7, true
			return c, iecSnapshot()
		},
	}
	for _, protocol := range []string{"modbus", "dnp3", "iec104"} {
		for _, cause := range []string{"master", "decoder"} {
			cases[protocol+"-"+cause] = func() (*Compiler, *rules.Snapshot) {
				c := NewCompiler()
				c.QueueID, c.NFLogGroup = 101, 100
				return c, &rules.Snapshot{DPIEnabled: cause != "master", DPIICSProtocols: map[string]bool{protocol: cause != "decoder"},
					Firewall: []rules.Entry{{ID: "guard", Action: rules.ActionAllow, Log: true, ICS: rules.ICSPredicate{Protocol: protocol, Mode: "enforce"}}}}
			}
		}
	}
	for _, g := range loweringGoldens {
		cases[g.file] = func() (*Compiler, *rules.Snapshot) { return g.compiler(), g.snapshot() }
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			c, snap := build()
			script, err := c.CompileFirewall(snap)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(ctx, "nft", "-c", "-f", "-")
			cmd.Stdin = strings.NewReader(script)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("nft rejects the ruleset: %v: %s", err, out)
			}
		})
	}
}
