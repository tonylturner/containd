// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"golang.org/x/sys/unix"
)

func TestInterfaceAttachmentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := ApplyInterfaces(ctx, []config.Interface{{Name: "not-attached", Addresses: []string{"192.0.2.1/24"}}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("unattached row hid cancellation: %v", err)
	}
}

func TestInterfaceAttachmentKernel(t *testing.T) {
	ctx := routingKernelContext(t)
	command := func(args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	if os.Getenv("CONTAIND_ATTACHMENT_HELPER") == "" {
		command("netns", "add", "interface-attachment")
		defer command("netns", "del", "interface-attachment")
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		child := exec.CommandContext(ctx, "ip", "netns", "exec", "interface-attachment", exe, "-test.run=^TestInterfaceAttachmentKernel$", "-test.v")
		child.Env = append(os.Environ(), "CONTAIND_ATTACHMENT_HELPER=1", "CONTAIND_ADDRESS_STATE_PATH="+filepath.Join(t.TempDir(), "addresses.json"))
		if out, err := child.CombinedOutput(); err != nil {
			t.Fatalf("namespace test: %v\n%s", err, out)
		}
		return
	}
	command("link", "add", "present", "type", "dummy")
	command("link", "add", "member", "type", "dummy")
	ifaces := []config.Interface{
		{Name: "late", Addresses: []string{"192.0.2.1/24"}},
		{Name: "dhcplate", AddressMode: "dhcp"},
		{Name: "present", Addresses: []string{"198.51.100.1/24"}},
		// Deliberately place virtual consumers before their dependencies.
		{Name: "brlate", Type: "bridge", Members: []string{"vlanlate", "member"}, Addresses: []string{"203.0.113.1/24"}},
		{Name: "vlanlate", Type: "vlan", Parent: "late", VLANID: 42},
		{Name: "member", AddressMode: "dhcp"},
	}
	apply := func() {
		t.Helper()
		if err := ApplyInterfaces(ctx, ifaces); err != nil {
			t.Fatal(err)
		}
	}
	hasAddress := func(dev, cidr string) bool {
		t.Helper()
		nic, err := net.InterfaceByName(dev)
		if err != nil {
			t.Fatal(err)
		}
		addrs, err := listAddrs(nic.Index, unix.AF_INET)
		if err != nil {
			t.Fatal(err)
		}
		for _, addr := range addrs {
			if addr.String() == cidr {
				return true
			}
		}
		return false
	}
	apply()
	if !hasAddress("present", "198.51.100.1/24") {
		t.Fatal("missing row stopped independent addressed row")
	}
	for _, dev := range []string{"vlanlate", "brlate"} {
		if _, err := net.InterfaceByName(dev); err == nil {
			t.Fatalf("%s created despite unattached dependency", dev)
		}
	}
	command("link", "add", "late", "type", "dummy")
	apply()
	if !hasAddress("late", "192.0.2.1/24") || !hasAddress("brlate", "203.0.113.1/24") {
		t.Fatal("late attachment did not converge addresses and virtual dependants")
	}
	if _, err := net.InterfaceByName("vlanlate"); err != nil {
		t.Fatal(err)
	}
	ifaces[2].Addresses = []string{"invalid-cidr"}
	if err := ApplyInterfaces(ctx, ifaces); err == nil {
		t.Fatal("real configuration error was suppressed")
	}
}
