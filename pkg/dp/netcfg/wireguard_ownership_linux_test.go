// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"golang.org/x/sys/unix"
)

func TestWireGuardOwnershipPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "links.json")
	t.Setenv("CONTAIND_WIREGUARD_STATE_PATH", path)
	s, err := loadWireGuardOwnership()
	if err != nil {
		t.Fatal(err)
	}
	s.Links = []ownedWireGuardLink{{Index: 17, Token: "containd-wireguard:0123456789abcdef0123456789abcdef"}}
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	got, err := loadWireGuardOwnership()
	if err != nil || !reflect.DeepEqual(got.Links, s.Links) {
		t.Fatalf("lost persisted links: %+v %v", got, err)
	}
	stat, err := os.Stat(path)
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatalf("ownership permissions: %v %v", stat, err)
	}
	for _, mismatch := range []string{"boot", "namespace"} {
		changed := *s
		if mismatch == "boot" {
			changed.BootID = "different-" + s.BootID
		} else {
			changed.Namespace = s.Namespace ^ 1
		}
		if err := changed.save(); err != nil {
			t.Fatal(err)
		}
		fresh, err := loadWireGuardOwnership()
		if err != nil || len(fresh.Links) != 0 {
			t.Fatalf("replayed old %s ownership: %+v %v", mismatch, fresh, err)
		}
	}
	for _, data := range []string{"{", fmt.Sprintf(`{"version":%d}`, s.Version^1)} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadWireGuardOwnership(); err == nil {
			t.Fatalf("accepted invalid state %q", data)
		}
	}
}

// Run in a disposable golang:1.26.10 container with NET_ADMIN and iproute2:
// CONTAIND_WIREGUARD_KERNEL_TEST=1 go test -run TestWireGuardOwnershipKernel ./pkg/dp/netcfg
func TestWireGuardOwnershipKernel(t *testing.T) {
	if os.Getenv("CONTAIND_WIREGUARD_KERNEL_TEST") != "1" {
		t.Skip("requires disposable Linux network namespace with NET_ADMIN")
	}
	t.Setenv("CONTAIND_WIREGUARD_STATE_PATH", filepath.Join(t.TempDir(), "links.json"))
	ctx := context.Background()
	cmd := func(args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	assertLink := func(name string, present bool) {
		t.Helper()
		_, err := net.InterfaceByName(name)
		if (err == nil) != present {
			t.Fatalf("%s present=%v, want=%v: %v", name, err == nil, present, err)
		}
	}
	apply := func(cfg config.WireGuardConfig) {
		t.Helper()
		if err := ApplyWireGuard(ctx, cfg); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.WireGuardConfig{Enabled: true, Interface: "ct-wg-old"}
	cmd("link", "add", "ct-wg-foreign", "type", "wireguard")
	defer cmd("link", "del", "ct-wg-foreign")
	apply(cfg)
	assertLink("ct-wg-old", true)
	cfg.Interface = "ct-wg-next"
	apply(cfg)
	assertLink("ct-wg-old", false)
	assertLink("ct-wg-next", true)

	// A failed delete is returned and retained for retry, not silently lost.
	owned, err := loadWireGuardOwnership()
	if err != nil {
		t.Fatal(err)
	}
	if err := owned.cleanup("", func(int) error { return unix.EPERM }); !errors.Is(err, unix.EPERM) {
		t.Fatalf("delete error lost: %v", err)
	}
	owned, err = loadWireGuardOwnership()
	if err != nil || len(owned.Links) != 1 {
		t.Fatalf("failed deletion lost retry authority: %+v %v", owned, err)
	}

	// Projection loses the custom name. Teardown must use durable ownership.
	desired := config.DefaultConfig()
	desired.Services.VPN.WireGuard = cfg
	desired.Services.VPN.WireGuard.ListenPort = 65536
	effective, faults, err := config.Effective(desired, nil)
	if err != nil || len(faults) != 1 || faults[0].Service != config.ServiceWireGuard {
		t.Fatalf("quarantine projection: %+v %v", faults, err)
	}
	apply(effective.Services.VPN.WireGuard)
	assertLink("ct-wg-next", false)
	assertLink("ct-wg-foreign", true)

	// Even an enabled exact-name match must never adopt an external link.
	cfg.Interface = "ct-wg-foreign"
	apply(cfg)
	apply(config.WireGuardConfig{})
	assertLink("ct-wg-foreign", true)

	// Kernel identity prevents a stale record from claiming foreign reuse.
	cfg.Interface = "ct-wg-reuse"
	apply(cfg)
	cmd("link", "set", cfg.Interface, "alias", "foreign")
	apply(config.WireGuardConfig{})
	assertLink(cfg.Interface, true)
	cmd("link", "del", cfg.Interface)

	// A fresh process must find and delete an owned custom-named link.
	cfg.Interface = "ct-wg-restart"
	apply(cfg)
	child := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestWireGuardOwnershipRestartHelper$")
	child.Env = append(os.Environ(), "CONTAIND_WIREGUARD_RESTART_HELPER=1")
	if out, err := child.CombinedOutput(); err != nil {
		t.Fatalf("restart teardown: %v %s", err, out)
	}
	assertLink(cfg.Interface, false)
}

func TestWireGuardOwnershipRestartHelper(t *testing.T) {
	if os.Getenv("CONTAIND_WIREGUARD_RESTART_HELPER") != "1" {
		t.Skip("isolated restart subprocess helper")
	}
	if err := ApplyWireGuard(context.Background(), config.WireGuardConfig{}); err != nil {
		t.Fatal(err)
	}
}
