// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// protectionPolicyInput includes management's namespace-resolved bindings as
// well as the resolved forwarding addresses and inspection signature. The
// compiler uses the same binding resolver; an unchanged logical listener can
// otherwise silently mean a different INPUT policy after an interface change.
func protectionPolicyInput(snap rules.Snapshot, signature [32]byte, discover func() ([]string, error)) ([]byte, error) {
	type binding struct {
		Index   int
		Devices []string
	}
	var bindings []binding
	var live []string
	discovered := false
	for i, rule := range snap.LocalInput {
		if !rule.RecoverUnbound || discover == nil {
			continue
		}
		if !discovered {
			var err error
			live, err = discover()
			if err != nil {
				return nil, err
			}
			discovered = true
		}
		devices, _ := mgmtpath.ResolveBindings(rule.Ifaces, rule.DeniedIfaces, live)
		bindings = append(bindings, binding{i, devices})
	}
	return canonicalPolicyJSON(struct {
		Snapshot   rules.Snapshot
		Signature  [32]byte
		Management []binding
	}{snap, signature, bindings})
}
