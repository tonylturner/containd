// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// shadowWarnings reports terminals covered by an earlier unconditional
// terminal. Effects and monitor rules cannot shadow a decision. IEC objects
// retain their separate partition, so plain rules cannot shadow IEC policy.
func shadowWarnings(snap *rules.Snapshot) []RuleWarning {
	var out []RuleWarning
	for i, d := range snap.Firewall {
		if !d.Action.Decides() || rules.MonitorICS(d, snap.DPIMode) {
			continue
		}
		for j, a := range snap.Firewall[:i] {
			if !a.Action.Decides() || rules.MonitorICS(a, snap.DPIMode) || !unconditional(a) || isIEC104Rule(d) != isIEC104Rule(a) {
				continue
			}
			if covers(a, d) {
				out = append(out, RuleWarning{RuleID: d.ID, ShadowedBy: a.ID, Action: d.Action,
					Message: fmt.Sprintf("rule at position %d is shadowed by earlier %s rule %s at position %d, which matches all of its traffic", i+1, a.Action, a.ID, j+1)})
				break
			}
		}
	}
	return out
}

// unconditional reports a terminal whose match depends on nothing but its
// L3/L4 scope and, at most, an ICS protocol: no identities, schedule or
// semantic ICS values.
func unconditional(a rules.Entry) bool {
	if a.HasIdentityPredicate() || a.HasSchedulePredicate() {
		return false
	}
	ics := a.ICS
	ics.Protocol, ics.Mode = "", ""
	return icsEmpty(ics)
}

// covers reports whether terminal a matches everything d matches.
func covers(a, d rules.Entry) bool {
	if p := a.ICS.Protocol; p != "" && !strings.EqualFold(p, d.ICS.Protocol) {
		return false
	}
	return zonesCover(a.ViaForwards, d.ViaForwards) && zonesCover(a.SourceZones, d.SourceZones) && zonesCover(a.DestZones, d.DestZones) &&
		prefixesCover(a.Sources, d.Sources) && prefixesCover(a.Destinations, d.Destinations) &&
		protocolsCover(a.Protocols, d.Protocols)
}

// zonesCover: an empty list matches every zone.
func zonesCover(a, d []string) bool {
	if len(a) == 0 {
		return true
	}
	if len(d) == 0 {
		return false
	}
	for _, z := range d {
		found := false
		for _, x := range a {
			found = found || x == z
		}
		if !found {
			return false
		}
	}
	return true
}

// prefixesCover: an empty list matches every address; each of d's
// prefixes must lie within one of a's.
func prefixesCover(a, d []string) bool {
	if len(a) == 0 {
		return true
	}
	if len(d) == 0 {
		return false
	}
	for _, ds := range d {
		dp, ok := parsePrefix(ds)
		if !ok {
			return false
		}
		found := false
		for _, as := range a {
			if ap, ok := parsePrefix(as); ok && ap.Bits() <= dp.Bits() && ap.Contains(dp.Addr()) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func parsePrefix(s string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// protocolsCover: no protocols matches everything; each of d's protocols
// must lie within one of a's.
func protocolsCover(a, d []rules.Protocol) bool {
	if len(a) == 0 {
		return true
	}
	if len(d) == 0 {
		return false
	}
	for _, dp := range d {
		found := false
		for _, ap := range a {
			if protocolCovers(ap, dp) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func protocolCovers(a, d rules.Protocol) bool {
	if an := protocolName(a); an != "" && an != protocolName(d) {
		return false
	}
	if a.Port == "" {
		return true
	}
	if d.Port == "" {
		return false
	}
	alo, ahi, aerr := rules.ParsePortRange(a.Port)
	dlo, dhi, derr := rules.ParsePortRange(d.Port)
	return aerr == nil && derr == nil && alo <= dlo && dhi <= ahi
}

// icsEmpty reports an ICS predicate with no field set.
func icsEmpty(p rules.ICSPredicate) bool {
	return p.Protocol == "" && len(p.FunctionCode) == 0 && p.UnitID == nil && len(p.Addresses) == 0 &&
		len(p.ObjectClasses) == 0 && !p.ReadOnly && !p.WriteOnly && p.Direction == "" && p.Mode == "" &&
		len(p.TypeIDs) == 0 && len(p.Classes) == 0 && len(p.CA) == 0 && len(p.IOA) == 0 &&
		len(p.COT) == 0 && len(p.Originators) == 0 && p.Negative == nil && p.Test == nil && p.SelectExecute == "" &&
		len(p.CommandStates) == 0 && len(p.CommandQualifiers) == 0 &&
		len(p.Masters) == 0 && len(p.Outstations) == 0 && len(p.Groups) == 0 && len(p.Variations) == 0 &&
		len(p.Instances) == 0 && len(p.Attributes) == 0 && len(p.Tags) == 0
}
