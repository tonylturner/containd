// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestApplianceDefaultsIncludeBootstrapAndSSH(t *testing.T) {
	t.Setenv("CONTAIND_ENFORCE_ENABLED", "1")
	t.Setenv("CONTAIND_CAPTURE_IFACES", "fixture0,fixture1")
	cfg := ApplianceDefaults(nil)
	if !cfg.DataPlane.Enforcement || len(cfg.DataPlane.CaptureInterfaces) != 2 || cfg.System.Hostname != "containd" || cfg.System.Mgmt.HTTPListenAddr != ":8080" || cfg.System.SSH.ListenAddr != ":2222" || cfg.System.SSH.AuthorizedKeysDir != "/data/ssh/authorized_keys.d" {
		t.Fatalf("incomplete appliance defaults: %+v", cfg)
	}
}

func TestApplianceDefaultsAvoidReservedListenerPort(t *testing.T) {
	for _, port := range []uint16{8080, 8443, 2222} {
		t.Run(fmt.Sprint(port), func(t *testing.T) {
			r := &mgmtpath.Reservation{Device: "fixture", Local: netip.MustParsePrefix("10.99.99.2/24"), Sources: []netip.Addr{netip.MustParseAddr("10.99.99.10")}, Port: port}
			cfg := ApplianceDefaults(r)
			if err := config.ValidateManagementListeners(cfg.System, r); err != nil {
				t.Fatal(err)
			}
			if !cfg.DataPlane.Enforcement {
				t.Fatal("reserved defaults disabled enforcement")
			}
		})
	}
}

func TestReservedAutoBindAfterRenumber(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataPlane.Enforcement = true
	var state []config.InterfaceState
	for i, name := range config.DefaultPhysicalInterfaces() {
		// The reserved NIC is now index/name 5, which used to hold addressed lan4.
		subnet := fmt.Sprintf("10.219.%d.0/24", i)
		t.Setenv("CONTAIND_AUTO_"+strings.ToUpper(name)+"_SUBNET", subnet)
		state = append(state, config.InterfaceState{Name: fmt.Sprintf("nic%d", (i+1)%8), Index: i + 1, Up: true, Addrs: []string{fmt.Sprintf("10.219.%d.2/24", i)}})
		// The boot normalizer has blanked stale default bindings; row values stay.
		if name == "lan4" {
			cfg.Interfaces[i].Addresses = []string{"192.0.2.14/24"}
		}
	}
	r := &mgmtpath.Reservation{Device: "nic5", Local: netip.MustParsePrefix("10.219.4.2/24"), Sources: []netip.Addr{netip.MustParseAddr("10.219.4.10")}, Port: 8080}
	if !autoBindDefaultInterfaceDevicesReservedFromState(cfg, state, "nic1", r) {
		t.Fatal("renumbering did not rebind")
	}
	if err := config.ValidateManagementReservation(cfg, r); err != nil {
		t.Fatal(err)
	}
	for _, iface := range cfg.Interfaces {
		if iface.Name == "lan4" && (iface.Device != "nic6" || len(iface.Addresses) != 1) {
			t.Fatalf("lost addressed ordinary row: %+v", iface)
		}
	}
}
