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

func partialNICState(t *testing.T, n, generation int) []config.InterfaceState {
	t.Helper()
	var state []config.InterfaceState
	for i, logical := range defaultInterfaceOrder() {
		t.Setenv("CONTAIND_AUTO_"+strings.ToUpper(logical)+"_SUBNET", fmt.Sprintf("10.219.%d.0/24", i))
		if i < n {
			state = append(state, config.InterfaceState{
				Name: fmt.Sprintf("eth%d", (i+generation)%n), Up: true, Index: i + 2,
				Addrs: []string{fmt.Sprintf("10.219.%d.2/24", i)},
			})
		}
	}
	return state
}

func TestPartialUniqueSubnetAssignments(t *testing.T) {
	for _, n := range []int{5, 7, 8} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			state := partialNICState(t, n, 1)
			cfg := config.DefaultConfig()
			if !autoBindDefaultInterfaceDevicesFromState(cfg, state, "eth0") {
				t.Fatal("no partial assignments")
			}
			for i, iface := range cfg.Interfaces {
				want := ""
				if i < n {
					want = fmt.Sprintf("eth%d", (i+1)%n)
				}
				if iface.Device != want {
					t.Fatalf("%s: got %q want %q", iface.Name, iface.Device, want)
				}
			}
			// Boot blanks default rows before discovery; renumbering must follow
			// subnets, not previous names, prefix hints or the default route.
			for i := range cfg.Interfaces {
				cfg.Interfaces[i].Device = ""
			}
			state = partialNICState(t, n, 2)
			if !autoBindDefaultInterfaceDevicesFromState(cfg, state, "eth0") {
				t.Fatal("no renumbered assignments")
			}
			if cfg.Interfaces[4].Device != fmt.Sprintf("eth%d", 6%n) {
				t.Fatalf("management did not follow subnet: %+v", cfg.Interfaces[4])
			}
		})
	}
}

func TestAmbiguousAndDownSubnetsRemainUnbound(t *testing.T) {
	state := partialNICState(t, 5, 0)
	state = append(state, config.InterfaceState{Name: "wan0", Up: true, Addrs: []string{"10.219.0.3/24"}})
	state[1].Up = false
	cfg := config.DefaultConfig()
	got, err := computeDefaultInterfaceAssignments(cfg.Interfaces, state, autoAssignOptions{AllowFallback: true, DefaultRouteIface: "wan0"})
	if err != nil {
		t.Fatal(err)
	}
	if got["wan"] != "" || got["dmz"] != "" || got["lan3"] != "eth4" || len(got) != 3 {
		t.Fatalf("unsafe/non-independent subnet assignment: %v", got)
	}
}

func TestDownDefaultRouteDeviceRemainsUnbound(t *testing.T) {
	t.Setenv("CONTAIND_AUTO_WAN_SUBNET", "")
	t.Setenv("CONTAIND_WAN_SUBNET", "")
	got, err := computeDefaultInterfaceAssignments(
		[]config.Interface{{Name: "wan"}},
		[]config.InterfaceState{{Name: "eth0", Up: false}},
		autoAssignOptions{DefaultRouteIface: "eth0"},
	)
	if err != nil || len(got) != 0 {
		t.Fatalf("bound a down default-route device: %v, %v", got, err)
	}
}

func TestPartialExplicitAssignmentSurvivesMissingFallbackNICs(t *testing.T) {
	state := partialNICState(t, 5, 0)
	// RD's five-NIC layout only supplies the five matching variables.
	for _, name := range []string{"lan4", "lan5", "lan6"} {
		t.Setenv("CONTAIND_AUTO_"+strings.ToUpper(name)+"_SUBNET", "")
		t.Setenv("CONTAIND_"+strings.ToUpper(name)+"_SUBNET", "")
	}
	got, err := computeDefaultInterfaceAssignments(config.DefaultConfig().Interfaces, state, autoAssignOptions{AllowFallback: true})
	if err != nil || len(got) != 5 || got["lan3"] != "eth4" {
		t.Fatalf("fallback discarded deterministic partial assignments: %v, %v", got, err)
	}
}

func TestReservationDefaultsWithPartialNICs(t *testing.T) {
	for _, n := range []int{5, 7} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			state := partialNICState(t, n, 1)
			r := &mgmtpath.Reservation{
				Device: fmt.Sprintf("eth%d", 5%n), Local: netip.MustParsePrefix("10.219.4.2/24"),
				Sources: []netip.Addr{netip.MustParseAddr("10.219.4.10")}, Port: 8080,
			}
			cfg := applianceDefaults(r, func(cfg *config.Config, r *mgmtpath.Reservation) bool {
				return autoBindDefaultInterfaceDevicesReservedFromState(cfg, state, "eth0", r)
			})
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			if err := config.ValidateManagementReservation(cfg, r); err != nil {
				t.Fatal(err)
			}
			if cfg.Interfaces[4].Device != r.Device {
				t.Fatal("reserved subnet not bound")
			}
		})
	}
}
