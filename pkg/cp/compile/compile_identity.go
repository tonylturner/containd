// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"slices"

	"github.com/tonylturner/containd/pkg/cp/config"
	dprules "github.com/tonylturner/containd/pkg/dp/rules"
)

// compileIdentityBindings copies validated bindings into the snapshot with
// canonical addresses, sorted by address, and sorted labels, so equal
// bindings compile to equal snapshots and rulesets.
func compileIdentityBindings(bindings []config.IdentityBinding) []dprules.IdentityBinding {
	if len(bindings) == 0 {
		return nil
	}
	out := make([]dprules.IdentityBinding, 0, len(bindings))
	for _, b := range bindings {
		addr, _ := dprules.BindingAddr(b.IP)
		ids := slices.Clone(b.Identities)
		slices.Sort(ids)
		out = append(out, dprules.IdentityBinding{IP: addr.String(), Identities: ids})
	}
	slices.SortFunc(out, func(a, b dprules.IdentityBinding) int {
		x, _ := dprules.BindingAddr(a.IP)
		y, _ := dprules.BindingAddr(b.IP)
		return x.Compare(y)
	})
	return out
}
