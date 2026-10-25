// SPDX-License-Identifier: Apache-2.0
package netcfg

import (
	"errors"
	"testing"
)

func TestManagementHealthStickyFaultAndSubscriptionState(t *testing.T) {
	var event ManagementFault
	g := &ManagementGuard{health: ManagementHealth{Active: true, Sources: []string{"10.99.99.10"}}, notify: func(f ManagementFault) { event = f }}
	g.fault(ManagementFault{Interface: "tun-test", Address: "10.99.99.10", Reason: "removed conflicting address"})
	g.setError(errors.New("subscription overflow"))
	g.setActive(false)
	g.setError(nil) // A successful outage rescan must not claim the subscription is healthy.
	status := g.Status()
	if status.Active || status.Error == "" || status.Faults != 1 || status.LastFault == nil || event.Time.IsZero() {
		t.Fatalf("outage/fault hidden: %+v event=%+v", status, event)
	}
	status.LastFault.Reason = "caller mutation"
	status.Sources[0] = "caller mutation"
	g.setActive(true)
	status = g.Status()
	if status.Error != "" || status.Faults != 1 || status.LastFault.Reason != event.Reason || status.Sources[0] != "10.99.99.10" {
		t.Fatalf("fault history aliased or lost after recovery: %+v", status)
	}
	if status := (*ManagementGuard)(nil).Status(); status.Active || status.Faults != 0 {
		t.Fatal(status)
	}
}
