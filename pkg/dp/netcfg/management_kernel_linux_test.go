// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Run only in the disposable Docker namespace described in management-reservation.md.
func TestManagementKernelMatrix(t *testing.T) {
	if os.Getenv("CONTAIND_MANAGEMENT_KERNEL_TEST") != "1" {
		t.Skip("requires opt-in isolated Docker, root, NET_ADMIN, SYS_ADMIN, iproute2, nft, Python and OpenVPN")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root and CAP_NET_ADMIN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := func(t *testing.T, args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
		return string(out)
	}
	command(t, "ip", "netns", "add", "c1peer")
	defer command(t, "ip", "netns", "del", "c1peer")
	command(t, "ip", "link", "add", "reserved", "type", "veth", "peer", "name", "peerlink")
	defer command(t, "ip", "link", "del", "reserved")
	command(t, "ip", "link", "set", "peerlink", "netns", "c1peer")
	command(t, "ip", "addr", "add", "10.99.99.2/24", "dev", "reserved")
	command(t, "ip", "link", "set", "reserved", "up")
	command(t, "ip", "link", "set", "lo", "up")
	command(t, "ip", "-n", "c1peer", "addr", "add", "10.99.99.10/24", "dev", "peerlink")
	command(t, "ip", "-n", "c1peer", "addr", "add", "10.99.99.3/32", "dev", "peerlink")
	command(t, "ip", "-n", "c1peer", "link", "set", "peerlink", "up")
	command(t, "ip", "-n", "c1peer", "link", "set", "lo", "up")
	command(t, "ip", "link", "add", "teaching", "type", "dummy")
	defer command(t, "ip", "link", "del", "teaching")
	command(t, "ip", "link", "set", "teaching", "up")
	command(t, "ip", "addr", "add", "192.0.2.2/24", "dev", "teaching")
	for _, path := range []string{"all", "reserved"} {
		data, err := os.ReadFile("/proc/sys/net/ipv4/conf/" + path + "/rp_filter")
		if err != nil || strings.TrimSpace(string(data)) != "1" {
			t.Fatalf("%s rp_filter must be 1: %s %v", path, data, err)
		}
	}
	t.Setenv("CONTAIND_MGMT_RESERVATION", `{"subnet":"10.99.99.0/24","sources":["10.99.99.10","10.99.99.3"],"listen":":8080"}`)
	r, err := mgmtpath.Load()
	if err != nil {
		t.Fatal(err)
	}
	if r.Device != "reserved" || r.Local.String() != "10.99.99.2/24" {
		t.Fatalf("live discovery lost host/interface identity: %+v", r)
	}
	faults := make(chan ManagementFault, 64)
	g, err := StartManagementGuard(ctx, r, func(f ManagementFault) { faults <- f })
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	ln, err := net.Listen("tcp4", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("ok"))
			c.Close()
		}
	}()
	defer func() { ln.Close(); <-done }()
	compiler := enforce.NewCompiler()
	compiler.ManagementReservation = r
	text, err := compiler.CompileFirewall(&rules.Snapshot{Default: rules.ActionDeny})
	if err != nil {
		t.Fatal(err)
	}
	nft := exec.CommandContext(ctx, "nft", "-f", "-")
	nft.Stdin = strings.NewReader(text)
	if out, err := nft.CombinedOutput(); err != nil {
		t.Fatalf("nft: %v %s", err, out)
	}
	connect := func(source string) error {
		program := fmt.Sprintf("import socket; s=socket.socket(); s.settimeout(1); s.bind(('%s',0)); s.connect(('10.99.99.2',8080)); assert s.recv(2)==b'ok'", source)
		out, err := exec.CommandContext(ctx, "ip", "netns", "exec", "c1peer", "python3", "-c", program).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		return nil
	}
	assertTCP := func(t *testing.T) {
		t.Helper()
		for _, s := range []string{"10.99.99.10", "10.99.99.3"} {
			if err := connect(s); err != nil {
				t.Fatalf("fresh TCP from %s: %v", s, err)
			}
		}
	}
	t.Run("baseline_exact_INPUT", func(t *testing.T) { assertTCP(t) })
	for _, priority := range []int{2, 9000, 10000} {
		t.Run(fmt.Sprintf("competing_policy_%d", priority), func(t *testing.T) {
			command(t, "ip", "route", "replace", "default", "dev", "teaching", "table", "201")
			command(t, "ip", "rule", "add", "priority", fmt.Sprint(priority), "lookup", "201")
			defer command(t, "ip", "rule", "del", "priority", fmt.Sprint(priority), "lookup", "201")
			assertTCP(t)
		})
	}
	t.Run("main_default", func(t *testing.T) {
		command(t, "ip", "route", "replace", "default", "dev", "teaching")
		defer command(t, "ip", "route", "del", "default", "dev", "teaching")
		assertTCP(t)
	})
	for _, name := range []string{"more_specific_main", "OpenVPN_pushed_32"} {
		t.Run(name, func(t *testing.T) {
			command(t, "ip", "route", "replace", "10.99.99.10/32", "dev", "teaching")
			defer command(t, "ip", "route", "del", "10.99.99.10/32", "dev", "teaching")
			assertTCP(t)
		})
	}
	t.Run("REPLACE_and_reconcile_keep_pin", func(t *testing.T) {
		for range 3 {
			if err := ApplyRoutingReplace(ctx, config.RoutingConfig{Routes: []config.StaticRoute{{Dst: "10.99.99.10/32", Iface: "teaching"}}, Rules: []config.PolicyRule{{Priority: 10000, Table: 201}}}); err != nil {
				t.Fatal(err)
			}
			if err := g.Reconcile(ctx); err != nil {
				t.Fatal(err)
			}
		}
		assertTCP(t)
		listing := command(t, "ip", "rule", "show")
		if got := strings.Count(listing, fmt.Sprintf("lookup %d", ManagementTable)); got != 2 {
			t.Fatalf("pin duplicated/deleted: %s", listing)
		}
	})
	t.Run("validator_rejects_priority1_and_source_address", func(t *testing.T) {
		if config.ValidateManagementRouting(config.RoutingConfig{Rules: []config.PolicyRule{{Priority: 1, Table: 201}}}, r) == nil {
			t.Fatal("accepted overlapping priority 1")
		}
		if config.ValidateManagementInterfaces([]config.Interface{{Name: "lan3", Device: "reserved"}, {Name: "wan", Device: "teaching", Addresses: []string{"10.99.99.10/32"}}}, r) == nil {
			t.Fatal("accepted source address")
		}
		for _, routing := range []config.RoutingConfig{
			{Rules: []config.PolicyRule{{Priority: 1 << 32, Table: 201}}},
			{Routes: []config.StaticRoute{{Dst: "0.0.0.0/0", Table: 255, Iface: "teaching"}}},
		} {
			if config.ValidateManagementRouting(routing, r) == nil {
				t.Fatal("partial API accepted numeric narrowing/local-table bypass")
			}
		}
	})
	t.Run("local_route_guard", func(t *testing.T) {
		count := g.Status().Faults
		command(t, "ip", "route", "add", "local", "10.99.99.10/32", "dev", "teaching", "table", "local")
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if g.Status().Faults > count && connect("10.99.99.10") == nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("local-route guard failed to recover TCP and expose fault")
	})
	t.Run("OpenVPN_source_takeover_recovers_and_faults", func(t *testing.T) {
		count := g.Status().Faults
		path := filepath.Join(t.TempDir(), "plain.ovpn")
		if err := os.WriteFile(path, []byte("dev tun-c1\nproto udp\nremote 127.0.0.1 1194\nifconfig 10.99.99.10 10.99.99.11\ncipher none\nauth none\nverb 3\n"), 0600); err != nil {
			t.Fatal(err)
		}
		var log bytes.Buffer
		cmd := exec.CommandContext(ctx, "openvpn", "--config", path, "--verb", "3")
		cmd.Stdout = &log
		cmd.Stderr = &log
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cmd.Process.Signal(os.Interrupt); _ = cmd.Wait(); t.Log("OpenVPN log:\n" + log.String()) }()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			status := g.Status()
			if status.Faults > count && status.LastFault != nil && status.LastFault.Address == "10.99.99.10" && status.LastFault.Interface == "tun-c1" && status.Error == "" && connect("10.99.99.10") == nil {
				assertTCP(t)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("OpenVPN takeover not repaired with visible health fault: %+v", g.Status())
	})
	if len(faults) == 0 {
		t.Fatal("health faults did not produce events")
	}
	t.Logf("visible fault/event: %+v", <-faults)
}
