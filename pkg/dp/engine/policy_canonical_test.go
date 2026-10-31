// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"slices"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestPolicySignatureCanonicalSetsNotDecisionOrder(t *testing.T) {
	e, _ := admissionEngine(t)
	snap := rules.Snapshot{Firewall: []rules.Entry{
		{ID: "first", Sources: []string{"192.0.2.1/32", "192.0.2.2/32"}, Action: rules.ActionAllow,
			ICS: rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3, 4}}},
		{ID: "second", Action: rules.ActionDeny, ICS: rules.ICSPredicate{Protocol: "iec104", TypeIDs: []int{45, 46}}},
	}}
	first, err := e.policySignature(snap)
	if err != nil {
		t.Fatal(err)
	}
	other := snap
	other.Version, other.AdmissionParity, other.DPIMode, other.Default = "metadata", 4, "monitor", rules.ActionDeny
	other.Firewall = slices.Clone(snap.Firewall)
	other.Firewall[0].Sources = []string{"192.0.2.2/32", "192.0.2.1/32", "192.0.2.1/32"}
	other.Firewall[0].ICS.FunctionCode = []uint8{4, 3, 3}
	other.Firewall[0].ICS.Mode = "monitor"
	other.Firewall[1].ViaForwards = []string{}
	other.Firewall[1].ICS.TypeIDs = []int{46, 45, 45}
	other.LocalInput = []rules.LocalServiceRule{{ID: "management", Port: 8080}}
	other.IDS.Rules = []rules.IDSRule{{ID: "alert", Description: "not permission"}}
	second, err := e.policySignature(other)
	if err != nil || first != second {
		t.Fatalf("effective no-op differs: %x %x %v", first, second, err)
	}
	slices.Reverse(other.Firewall)
	third, err := e.policySignature(other)
	if err != nil || third == first {
		t.Fatal("configured terminal order vanished from fingerprint")
	}
}
