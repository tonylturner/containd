// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Recovery has its own deliberately short dependency order. It must never wait
// for ordinary network, trust or service convergence before dropping transit.
func (c *protectionCoordinator) recoveryPhase(w http.ResponseWriter, phase string, body []byte, current bool) bool {
	valid := false
	switch phase {
	case "config":
		var dp config.DataPlaneConfig
		valid = json.Unmarshal(body, &dp) == nil && reflect.DeepEqual(dp, config.DataPlaneConfig{Enforcement: true})
	case "nft":
		var snap rules.Snapshot
		if json.Unmarshal(body, &snap) == nil {
			expected := rules.Snapshot{Version: config.ManagementRecoveryVersion, Default: rules.ActionDeny, LocalInput: snap.LocalInput}
			valid = current && c.completed["config"] && reflect.DeepEqual(snap, expected)
			for _, rule := range snap.LocalInput {
				id := strings.TrimSuffix(rule.ID, "-bound")
				valid = valid && (id == "auto-allow-mgmt-http" || id == "auto-allow-mgmt-https" || id == "auto-allow-ssh") &&
					rule.Proto == "tcp" && rule.Port > 0 && rule.Port <= 65535 && rule.Zone == ""
			}
		}
	case "interfaces":
		var ifaces []config.Interface
		var snap rules.Snapshot
		_, input, _ := strings.Cut(c.inputs["nft"], "\n")
		if json.Unmarshal(body, &ifaces) == nil && json.Unmarshal([]byte(input), &snap) == nil {
			valid = current && c.completed["nft"]
			for _, iface := range ifaces {
				addressOnly := config.Interface{Name: iface.Name, Device: iface.Device, Addresses: iface.Addresses}
				admitted := false
				for _, rule := range snap.LocalInput {
					admitted = admitted || slices.Contains(rule.Ifaces, iface.Device)
				}
				valid = valid && admitted && iface.Device != "" && len(iface.Addresses) > 0 && reflect.DeepEqual(iface, addressOnly)
				for _, address := range iface.Addresses {
					_, err := netip.ParsePrefix(address)
					valid = valid && err == nil
				}
			}
		}
	}
	if !valid {
		protectionError(w, http.StatusConflict, "invalid_recovery_phase", "recovery requires fail-closed config, recovery rules, then admitted management addresses")
	}
	return valid
}
