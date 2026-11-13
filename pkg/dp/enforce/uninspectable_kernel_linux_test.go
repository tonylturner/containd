// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Even an admitting queue consumer, a prior broad ALLOW and a permissive
// default cannot admit an enforce scope whose inspection is unavailable.
func TestKernelUninspectableEnforceDrops(t *testing.T) {
	lab := orderedLab(t)
	repeatPolicyQueue(t, lab.ctx, 94, false)
	for _, tc := range []struct {
		proto string
		port  int
	}{{"modbus", 502}, {"dnp3", 20000}, {"iec104", 2404}} {
		lab.serveTarget(t, "198.18.70.2", tc.port)
		for _, cause := range []string{"master", "decoder"} {
			for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
				t.Run(fmt.Sprintf("%s/%s/%s", tc.proto, cause, action), func(t *testing.T) {
					snap := &rules.Snapshot{DPIEnabled: cause != "master", DPIICSProtocols: map[string]bool{tc.proto: cause != "decoder"}, Default: rules.ActionAllow,
						Firewall: []rules.Entry{
							{ID: "broad", Action: rules.ActionAllow},
							{ID: "guard", Action: action, Log: true, Protocols: []rules.Protocol{{Name: "tcp", Port: strconv.Itoa(tc.port)}},
								Identities: []string{"unbound"}, Schedule: maintenanceWindow, ICS: rules.ICSPredicate{Protocol: tc.proto, Mode: "enforce", ReadOnly: true}},
						}}
					c := NewCompiler()
					c.QueueID = 94
					c.IEC104EnvelopeOpen = true
					lab.apply(t, c, snap)
					if err := lab.probe("198.18.70.2", tc.port, "198.18.60.2"); err == nil {
						t.Error("uninspectable enforce scope admitted traffic")
					}
					if n := lab.counts(t, c, snap)["guard"].Packets; n == 0 {
						t.Error("transport drop did not hit rule counter")
					}
				})
			}
		}
	}
}
