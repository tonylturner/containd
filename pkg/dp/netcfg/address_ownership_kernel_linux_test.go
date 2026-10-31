// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/config"
	"golang.org/x/sys/unix"
)

// Run only in a disposable privileged Linux container, never a live engine:
//
//	GOOS=linux CGO_ENABLED=0 go test -c -o build/netcfg.test ./pkg/dp/netcfg
//	docker run --rm --privileged -e CONTAIND_NETNS_KERNEL_TEST=1 -v "$PWD/build:/w" alpine:3.21 \
//	  sh -c "apk add -q iproute2 && /w/netcfg.test -test.run 'Address.*Kernel' -test.v"
func TestAddressOwnershipKernel(t *testing.T) {
	ctx := routingKernelContext(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := func(args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	ns := "address-ownership"
	cmd("netns", "add", ns)
	defer cmd("netns", "del", ns)
	child := exec.CommandContext(ctx, "ip", "netns", "exec", ns, exe, "-test.run=^TestAddressOwnershipKernelHelper$", "-test.v")
	child.Env = append(os.Environ(), "CONTAIND_ADDRESS_HELPER=setup", "CONTAIND_ADDRESS_STATE_PATH="+filepath.Join(t.TempDir(), "addresses.json"))
	if out, err := child.CombinedOutput(); err != nil {
		t.Fatalf("namespace test: %v\n%s", err, out)
	}
}

func TestAddressOwnershipKernelHelper(t *testing.T) {
	mode := os.Getenv("CONTAIND_ADDRESS_HELPER")
	if mode == "" {
		t.Skip("isolated namespace subprocess helper")
	}
	ctx := routingKernelContext(t)
	const dev = "addrprobe"
	apply := func(addrs ...string) {
		t.Helper()
		if err := ApplyInterfaces(ctx, []config.Interface{{Name: dev, Addresses: addrs}}); err != nil {
			t.Fatal(err)
		}
	}
	assert := func(cidr string, want bool) {
		t.Helper()
		nic, err := net.InterfaceByName(dev)
		if err != nil {
			t.Fatal(err)
		}
		addrs, err := listAddrs(nic.Index, unix.AF_UNSPEC)
		if err != nil {
			t.Fatal(err)
		}
		present := false
		for _, a := range addrs {
			present = present || a.String() == cidr
		}
		if present != want {
			t.Fatalf("%s present=%v want=%v: %v", cidr, present, want, addrs)
		}
	}
	if mode == "restart" {
		apply("192.0.2.20/24")
		assert("192.0.2.19/24", false)
		assert("192.0.2.20/24", true)
		assert("192.0.2.1/24", true)
		assert("192.0.2.2/24", true)
		assert("fe80::123/64", true)
		return
	}
	cmd := func(args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	cmd("link", "add", dev, "type", "dummy")
	cmd("link", "set", dev, "up")
	// Legacy/foreign primary and secondary have no ownership record.
	cmd("addr", "add", "192.0.2.1/24", "dev", dev)
	cmd("addr", "add", "192.0.2.2/24", "dev", dev)
	cmd("-6", "addr", "add", "fe80::123/64", "dev", dev, "nodad")
	// An exact match satisfies intent, but must not be adopted.
	apply("192.0.2.1/24", "192.0.2.19/24", "2001:db8::19/64")
	apply("192.0.2.19/24")
	assert("192.0.2.1/24", true)
	assert("192.0.2.2/24", true)
	assert("2001:db8::19/64", false)
	restart := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestAddressOwnershipKernelHelper$", "-test.v")
	restart.Env = append(os.Environ(), "CONTAIND_ADDRESS_HELPER=restart")
	if out, err := restart.CombinedOutput(); err != nil {
		t.Fatalf("restart: %v %s", err, out)
	}
	// Removing the last address and removing the whole binding both converge.
	apply()
	assert("192.0.2.20/24", false)
	apply("192.0.2.21/24")
	if err := ApplyInterfaces(ctx, nil); err != nil {
		t.Fatal(err)
	}
	assert("192.0.2.21/24", false)
	assert("192.0.2.1/24", true)

	// Most importantly, an owned primary must not take a foreign secondary
	// with it, even when promote_secondaries starts disabled.
	cmd("link", "add", "ownedprimary", "type", "dummy")
	iface := config.Interface{Name: "ownedprimary", Addresses: []string{"198.51.100.1/24"}}
	if err := ApplyInterfaces(ctx, []config.Interface{iface}); err != nil {
		t.Fatal(err)
	}
	cmd("addr", "add", "198.51.100.2/24", "dev", iface.Name)
	promote := "/proc/sys/net/ipv4/conf/ownedprimary/promote_secondaries"
	nic, err := net.InterfaceByName(iface.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := setIPv4SecondaryPromotion(nic.Index, 0); err != nil {
		t.Fatal(err)
	}
	iface.Addresses = []string{"198.51.100.3/24"}
	if err := ApplyInterfaces(ctx, []config.Interface{iface}); err != nil {
		t.Fatal(err)
	}
	got, err := listAddrs(nic.Index, unix.AF_INET)
	if err != nil || len(got) != 2 || got[0].String() != "198.51.100.2/24" || got[1].String() != "198.51.100.3/24" {
		t.Fatalf("owned primary deletion lost foreign/desired secondary: %v %v", got, err)
	}
	old, err := os.ReadFile(promote)
	if err != nil || string(old) != "0\n" {
		t.Fatalf("promotion setting not restored: %q %v", old, err)
	}

	// Management remains untouched even if it used to be containd-owned.
	r := &mgmtpath.Reservation{Device: iface.Name, Local: netip.MustParsePrefix("198.51.100.3/24")}
	if err := ApplyInterfacesWithOptions(ctx, []config.Interface{{Name: iface.Name, Addresses: []string{"198.51.100.99/24"}}}, ApplyOptions{Replace: true, Reservation: r}); err != nil {
		t.Fatal(err)
	}
	got, err = listAddrs(nic.Index, unix.AF_INET)
	if err != nil || len(got) != 2 {
		t.Fatalf("reserved device changed: %v %v", got, err)
	}
	// Only explicit Replace may remove the unowned legacy addresses.
	if err := ApplyInterfacesReplace(ctx, []config.Interface{{Name: dev, Addresses: []string{"192.0.2.99/24"}}}); err != nil {
		t.Fatal(err)
	}
	assert("192.0.2.1/24", false)
	assert("192.0.2.2/24", false)
	assert("192.0.2.99/24", true)
	assert("fe80::123/64", true)
}
