// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"errors"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWireGuardAddressFailuresRemainUnacknowledged(t *testing.T) {
	old, err := parseAddressCIDR("192.0.2.1/24")
	if err != nil {
		t.Fatal(err)
	}
	refused := errors.New("kernel refused")
	for _, failure := range []string{"list", "remove", "add", "none", "clear", "invalid"} {
		t.Run(failure, func(t *testing.T) {
			removed, added, listed := 0, 0, 0
			list := func(index, family int) ([]*net.IPNet, error) {
				listed++
				if index != 7 || family != unix.AF_INET {
					t.Fatal("wrong address namespace")
				}
				if failure == "list" {
					return nil, refused
				}
				return []*net.IPNet{old, old}, nil
			}
			remove := func(int, *net.IPNet) error {
				removed++
				if failure == "remove" && removed == 2 {
					return refused // partial kernel mutation is not success
				}
				return nil
			}
			add := func(int, *net.IPNet) error {
				added++
				if failure == "add" {
					return refused
				}
				return nil
			}
			cidr := "192.0.2.2/24"
			if failure == "clear" {
				cidr = ""
			}
			if failure == "invalid" {
				cidr = "bad"
			}
			err := replaceWireGuardAddresses(7, cidr, list, remove, add)
			switch failure {
			case "list", "remove", "add":
				if !errors.Is(err, refused) {
					t.Fatalf("lost owner failure: %v", err)
				}
			case "invalid":
				if err == nil || listed != 0 {
					t.Fatal("invalid input mutated addresses")
				}
			default:
				wantAdded := 1
				if failure == "clear" {
					wantAdded = 0
				}
				if err != nil || removed != 2 || added != wantAdded {
					t.Fatalf("incomplete owner success: removed=%d added=%d err=%v", removed, added, err)
				}
			}
		})
	}
}
