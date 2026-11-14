// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"slices"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

func pairContextsCharge(contexts []rules.EvalContext) int64 {
	n := int64(0)
	for _, c := range contexts {
		n += 1024 + int64(len(c.SrcIP)+len(c.DstIP)+len(c.Identities)*16)
		for _, v := range c.Identities {
			n += int64(len(v))
		}
		if c.ICS != nil {
			n += int64(len(c.ICS.Spans)*8 + len(c.ICS.Symbol)*16)
			for _, v := range c.ICS.Symbol {
				n += int64(len(v))
			}
		}
	}
	return n
}
func pairCopyContexts(contexts []rules.EvalContext) []rules.EvalContext {
	out := slices.Clone(contexts)
	for i := range out {
		c := &out[i]
		c.SrcIP, c.DstIP = slices.Clone(c.SrcIP), slices.Clone(c.DstIP)
		c.Identities = slices.Clone(c.Identities)
		c.Conntrack = pairCopyPtr(c.Conntrack)
		if c.ICS == nil {
			continue
		}
		c.ICS = pairCopyPtr(c.ICS)
		o := c.ICS
		o.UnitID = pairCopyPtr(o.UnitID)
		o.Master, o.Outstation = pairCopyPtr(o.Master), pairCopyPtr(o.Outstation)
		o.Group, o.Variation = pairCopyPtr(o.Group), pairCopyPtr(o.Variation)
		o.Instance, o.Attribute = pairCopyPtr(o.Instance), pairCopyPtr(o.Attribute)
		o.Spans, o.Symbol = slices.Clone(o.Spans), slices.Clone(o.Symbol)
		if o.IEC104 == nil {
			continue
		}
		o.IEC104 = pairCopyPtr(o.IEC104)
		v := o.IEC104
		v.TypeID, v.COT, v.Originator = pairCopyPtr(v.TypeID), pairCopyPtr(v.COT), pairCopyPtr(v.Originator)
		v.CA, v.IOA = pairCopyPtr(v.CA), pairCopyPtr(v.IOA)
		v.Negative, v.Test, v.Select = pairCopyPtr(v.Negative), pairCopyPtr(v.Test), pairCopyPtr(v.Select)
		v.CommandState, v.CommandQualifier = pairCopyPtr(v.CommandState), pairCopyPtr(v.CommandQualifier)
	}
	return out
}
