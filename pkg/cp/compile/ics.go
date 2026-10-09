// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package compile

import (
	"github.com/tonylturner/containd/pkg/cp/config"
	dprules "github.com/tonylturner/containd/pkg/dp/rules"
)

// ICSPredicate is the one CP→DP mapping of an ICS predicate.
//
// Direction and ObjectClasses are not copied yet: the data-plane evaluator
// already matches them, so copying them changes US enforcement (spec §4.1
// item 2) and belongs in its own commit.
func ICSPredicate(p config.ICSPredicate) dprules.ICSPredicate {
	out := dprules.ICSPredicate{
		Protocol:     p.Protocol,
		FunctionCode: append([]uint8(nil), p.FunctionCode...),
		Addresses:    append([]string(nil), p.Addresses...),
		ReadOnly:     p.ReadOnly,
		WriteOnly:    p.WriteOnly,
		Mode:         p.Mode,
		TypeIDs:      append([]int(nil), p.TypeIDs...),
		Classes:      append([]string(nil), p.Classes...),
		CA:           append([]uint16(nil), p.CA...),
	}
	if p.UnitID != nil {
		unitID := *p.UnitID
		out.UnitID = &unitID
	}
	if len(p.IOA) > 0 {
		out.IOA = make([]dprules.IOARange, len(p.IOA))
		for i, r := range p.IOA {
			out.IOA[i] = dprules.IOARange{Start: r.Start, End: r.End}
		}
	}
	return out
}
