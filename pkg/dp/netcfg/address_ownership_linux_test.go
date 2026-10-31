// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
)

func TestAddressDeletionOwnership(t *testing.T) {
	reserved := &mgmtpath.Reservation{Local: netip.MustParsePrefix("10.99.99.2/24")}
	for _, tc := range []struct {
		name, cidr              string
		owned, desired, replace bool
		reservation             *mgmtpath.Reservation
		skip                    bool
	}{
		{name: "foreign primary", cidr: "192.0.2.1/24", skip: true},
		{name: "foreign secondary", cidr: "192.0.2.2/24", skip: true},
		{name: "owned stale", cidr: "192.0.2.3/24", owned: true},
		{name: "owned desired", cidr: "192.0.2.3/24", owned: true, desired: true, skip: true},
		{name: "foreign desired", cidr: "192.0.2.3/24", desired: true, skip: true},
		{name: "IPv6 foreign", cidr: "2001:db8::1/64", skip: true},
		{name: "IPv6 owned stale", cidr: "2001:db8::2/64", owned: true},
		{name: "link local owned", cidr: "fe80::1/64", owned: true, skip: true},
		{name: "link local replace", cidr: "fe80::1/64", replace: true, skip: true},
		{name: "reserved owned", cidr: "10.99.99.2/24", owned: true, reservation: reserved, skip: true},
		{name: "reserved replace different mask", cidr: "10.99.99.2/32", replace: true, reservation: reserved, skip: true},
		{name: "explicit foreign replacement", cidr: "192.0.2.1/24", replace: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := parseAddressCIDR(tc.cidr)
			if err != nil {
				t.Fatal(err)
			}
			desired := map[string]struct{}{}
			if tc.desired {
				desired[tc.cidr] = struct{}{}
			}
			if got := skipAddrDeletion(addr, desired, tc.owned, ApplyOptions{Replace: tc.replace, Reservation: tc.reservation}); got != tc.skip {
				t.Fatalf("skip=%v want %v", got, tc.skip)
			}
		})
	}
	if !skipAddrDeletion(nil, nil, true, ApplyOptions{Replace: true}) {
		t.Fatal("nil address was selected for deletion")
	}
}

func TestAddressOwnershipPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine", "addresses.json")
	t.Setenv("CONTAIND_ADDRESS_STATE_PATH", path)
	s, err := loadAddressOwnership()
	if err != nil {
		t.Fatal(err)
	}
	nic := &net.Interface{Name: "eth7", Index: 17, HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 7}}
	s.Addresses = []ownedAddress{addressKey(nic, "192.0.2.1/24")}
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadAddressOwnership()
	if err != nil || !loaded.owns(nic, "192.0.2.1/24") {
		t.Fatalf("lost persisted ownership: %v", err)
	}
	stat, err := os.Stat(path)
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatalf("journal permissions: %v %v", stat, err)
	}
	reused := *nic
	reused.Index++
	if loaded.owns(&reused, "192.0.2.1/24") {
		t.Fatal("adopted a recreated device")
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
		fresh, err := loadAddressOwnership()
		if err != nil || len(fresh.Addresses) != 0 {
			t.Fatalf("replayed old %s ownership: %+v %v", mismatch, fresh, err)
		}
	}
	for _, data := range []string{"{", fmt.Sprintf(`{"version":%d}`, s.Version^1)} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadAddressOwnership(); err == nil {
			t.Fatalf("accepted invalid state %q", data)
		}
	}
}
