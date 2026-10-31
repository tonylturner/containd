// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"golang.org/x/sys/unix"
)

func TestParseAddressCIDRPreservesHost(t *testing.T) {
	for _, cidr := range []string{"10.99.99.2/24", "192.0.2.19/27", "2001:db8::42/64"} {
		t.Run(cidr, func(t *testing.T) {
			addr, err := parseAddressCIDR(" " + cidr + " ")
			if err != nil {
				t.Fatal(err)
			}
			if addr.String() != cidr {
				t.Fatalf("got %s, want host address %s", addr, cidr)
			}
			// Static desired addresses are serialized, then parsed again before
			// netlink application. Both conversions must retain the host IP.
			roundTrip, err := parseAddressCIDR(addr.String())
			if err != nil || !roundTrip.IP.Equal(addr.IP) {
				t.Fatalf("round trip: %v, %v", roundTrip, err)
			}
		})
	}
	for _, invalid := range []string{"", "10.99.99.2", "10.99.99.2/33", "not-a-cidr"} {
		if _, err := parseAddressCIDR(invalid); err == nil {
			t.Errorf("accepted invalid CIDR %q", invalid)
		}
	}
}

func TestDesiredInterfaceAddrsPreservesHost(t *testing.T) {
	iface := config.Interface{Name: "test", Addresses: []string{"10.99.99.2/24", "2001:db8::42/64"}}
	all, err := desiredInterfaceAddrs(context.Background(), iface)
	if err != nil {
		t.Fatal(err)
	}
	for _, cidr := range iface.Addresses {
		if _, ok := all[cidr]; !ok {
			t.Errorf("desired addresses missing %s: %v", cidr, all)
		}
	}
	if len(all) != 2 {
		t.Fatalf("unexpected desired set: %v", all)
	}
	for _, cidr := range []string{"10.99.99.0/24", "2001:db8::/64"} {
		if _, ok := all[cidr]; ok {
			t.Errorf("network address leaked into desired set: %s", cidr)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := desiredInterfaceAddrs(ctx, iface); err == nil {
		t.Fatal("accepted canceled context")
	}
	if _, err := desiredInterfaceAddrs(context.Background(), config.Interface{Addresses: []string{"bad"}}); err == nil {
		t.Fatal("accepted invalid address")
	}
}

func TestAddressCIDRKernelPreservesHost(t *testing.T) {
	routingKernelContext(t)
	t.Setenv("CONTAIND_ADDRESS_STATE_PATH", filepath.Join(t.TempDir(), "addresses.json"))
	device := fmt.Sprintf("cidr%d", os.Getpid())
	if _, err := net.InterfaceByName(device); err == nil {
		t.Fatalf("test device %s already exists", device)
	}
	if err := ensureBridge(device); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skip("requires CAP_NET_ADMIN in an isolated network namespace")
		}
		t.Fatal(err)
	}
	defer func() {
		if err := deleteLink(device); err != nil {
			t.Errorf("delete test bridge: %v", err)
		}
	}()
	nic, err := net.InterfaceByName(device)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := parseAddressCIDR("10.99.99.2/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := addAddr(nic.Index, addr); err != nil {
		t.Fatal(err)
	}
	got, err := listAddrs(nic.Index, unix.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].String() != "10.99.99.2/24" {
		t.Fatalf("kernel addresses = %v, want 10.99.99.2/24", got)
	}
	iface := config.Interface{Name: device, Addresses: []string{"10.99.99.19/24"}}
	if err := ApplyInterfaces(context.Background(), []config.Interface{iface}); err != nil {
		t.Fatal(err)
	}
	got, err = listAddrs(nic.Index, unix.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].String() != "10.99.99.2/24" || got[1].String() != "10.99.99.19/24" {
		t.Fatalf("static addresses = %v, want foreign .2 and desired .19", got)
	}
}
