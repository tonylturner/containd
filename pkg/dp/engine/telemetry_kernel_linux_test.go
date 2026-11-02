// SPDX-License-Identifier: Apache-2.0
//go:build linux

package engine

import (
	"bufio"
	"os/exec"
	"testing"

	wire "github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Exercise the real install/read path: epochs come from the running engine,
// not a standalone compiler build retained by the test.
func TestTelemetryAccountingKernelLifecycle(t *testing.T) {
	ctx := newFirstCommandLab(t)
	store := events.NewStore(4096)
	makeEngine := func(enabled bool, table string) *Engine {
		t.Helper()
		e, err := New(Config{Events: store, Enforce: EnforceConfig{Enabled: enabled, TableName: table, ClearMark: noPolicyMarks}})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	e := makeEngine(true, "accounting_live")
	t.Cleanup(func() {
		if err := e.gate.release(); err != nil {
			t.Error(err)
		}
		e.Close()
	})
	ifaces := []config.Interface{{Name: "fc0", Zone: "client"}, {Name: "fc1", Zone: "server"}}
	if err := e.SetTelemetryInterfaces(ctx, ifaces); err != nil {
		t.Fatal(err)
	}
	snap := rules.Snapshot{Default: rules.ActionAllow, ZoneIfaces: map[string][]string{"client": {"fc0"}, "server": {"fc1"}}}
	apply := func() {
		t.Helper()
		if err := e.ApplyRules(ctx, snap); err != nil {
			t.Fatal(err)
		}
	}
	apply()
	server := exec.CommandContext(ctx, "ip", "netns", "exec", fcServerNS, "python3", "-u", "-c", `import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("198.18.60.2",18010));print("ready",flush=True)
while True:
 d,a=s.recvfrom(128);s.sendto(d,a)
`)
	ready, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	if !bufio.NewScanner(ready).Scan() {
		t.Fatal("UDP server did not start")
	}
	probe := func() {
		t.Helper()
		fcRun(ctx, t, "ip", "netns", "exec", fcClientNS, "python3", "-c", `import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.connect(("198.18.60.2",18010))
for i in range(3):
 s.send(b"ping");assert s.recv(128)==b"ping"
`)
	}
	check := func(from string, want uint64) string {
		t.Helper()
		samples, missing := e.TelemetryConduits(ctx)
		if len(missing) != 0 || len(samples) != 4 {
			t.Fatalf("samples=%+v unavailable=%+v", samples, missing)
		}
		epoch := ""
		for _, s := range samples {
			if epoch == "" {
				epoch = s.Epoch
			}
			if s.Epoch != epoch {
				t.Fatal("mixed epochs")
			}
			if s.Metric == wire.ConduitPackets && s.Value != want {
				t.Fatalf("%+v: want %d packets", s, want)
			}
			if s.Dims["from"] == from && s.Dims["to"] == "server" {
				continue
			}
			if s.Dims["from"] != "server" || s.Dims["to"] != from {
				t.Fatalf("unexpected dimensions: %+v", s.Dims)
			}
		}
		return epoch
	}
	original := check("client", 0)
	probe()
	check("client", 3)
	apply()
	if got := check("client", 3); got != original {
		t.Fatal("policy apply restarted accounting epoch")
	}
	ifaces[0].Zone = "moved"
	if err := e.SetTelemetryInterfaces(ctx, ifaces); err != nil {
		t.Fatal(err)
	}
	rebuilt := check("moved", 0)
	if rebuilt == original {
		t.Fatal("membership rebuild reused epoch")
	}
	probe()
	check("moved", 3)
	replace := func(enabled bool, table string) {
		t.Helper()
		fresh := makeEngine(enabled, table)
		if err := e.Reconfigure(fresh); err != nil {
			fresh.Close()
			t.Fatal(err)
		}
	}
	replace(false, "")
	if _, missing := e.TelemetryConduits(ctx); len(missing) != 1 || missing[0].Reason != "enforcement disabled" {
		t.Fatal(missing)
	}
	if _, err := enforce.NewNftApplier().ReadAccountingCounters(ctx, "accounting_live_acct"); err == nil {
		t.Fatal("disabled enforcement kept accounting table")
	}
	replace(true, "accounting_live")
	apply()
	enabled := check("moved", 0)
	if enabled == rebuilt {
		t.Fatal("reenable reused epoch")
	}
	probe()
	check("moved", 3)
	replace(true, "accounting_renamed")
	apply()
	if renamed := check("moved", 0); renamed == enabled {
		t.Fatal("rename reused epoch")
	}
	if _, err := enforce.NewNftApplier().ReadAccountingCounters(ctx, "accounting_live_acct"); err == nil {
		t.Fatal("rename kept old accounting table")
	}
	probe()
	check("moved", 3)
}
