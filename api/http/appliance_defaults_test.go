// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"fmt"
	"net/netip"
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
