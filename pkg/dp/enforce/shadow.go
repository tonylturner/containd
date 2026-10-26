// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// shadowWarnings reports each DENY or RESET rule that an ALLOW rule
// shadows: the ALLOW matches every packet and ICS message the rule
// matches, and any matching ALLOW takes precedence (rules.DecisionOrder),
// so the rule never decides anything. The check is sound, not complete: a
// rule covered only by several ALLOWs together is not reported. IEC104
// rules are left out: their objects are decided among IEC104 rules alone.
func shadowWarnings(snap *rules.Snapshot) []RuleWarning {
	var allows []rules.Entry
	for _, e := range snap.Firewall {
		if e.Action == rules.ActionAllow && unconditional(e) {
			allows = append(allows, e)
		}
	}
	sort.SliceStable(allows, func(i, j int) bool { return allows[i].ID < allows[j].ID })
	var out []RuleWarning
	for _, d := range snap.Firewall {
		if (d.Action != rules.ActionDeny && d.Action != rules.ActionReset) || isIEC104Rule(d) {
			continue
		}
		for _, a := range allows {
			if covers(a, d) {
				out = append(out, RuleWarning{
					RuleID: d.ID, ShadowedBy: a.ID, Action: d.Action,
					Message: "shadowed by ALLOW rule " + a.ID + ", which matches all of its traffic; a matching ALLOW takes precedence over every " + string(rules.ActionDeny) + " and " + string(rules.ActionReset),
				})
				break
			}
		}
	}
	return out
}

// unconditional reports an ALLOW whose match depends on nothing but its
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

// covers reports whether ALLOW a matches everything d matches.
func covers(a, d rules.Entry) bool {
	if p := a.ICS.Protocol; p != "" && !strings.EqualFold(p, d.ICS.Protocol) {
		return false
	}
	return zonesCover(a.SourceZones, d.SourceZones) && zonesCover(a.DestZones, d.DestZones) &&
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
		len(p.TypeIDs) == 0 && len(p.Classes) == 0 && len(p.CA) == 0 && len(p.IOA) == 0
}
