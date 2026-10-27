// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// zoneIndex maps each zone that has interfaces to their names as nft
// strings, sorted. A zone without interfaces is absent: a rule line that
// needs one of its interfaces matches nothing, so it is left out, and
// RuleWarnings reports the rule.
type zoneIndex map[string][]string

// newZoneIndex quotes the interfaces of every zone, refusing a name that
// ValidateInterfaceName refuses and a zone with interfaces whose name is
// too long to name its set.
func newZoneIndex(zoneIfaces map[string][]string) (zoneIndex, error) {
	idx := zoneIndex{}
	for z, ifaces := range zoneIfaces {
		for _, name := range ifaces {
			lit, err := ifnameLiteral(name)
			if err != nil {
				return nil, fmt.Errorf("zone %s: %w", z, err)
			}
			idx[z] = append(idx[z], lit)
		}
		if lits := idx[z]; len(lits) > 0 {
			if len(z) > MaxZoneNameBytes {
				return nil, fmt.Errorf("zone %q: a zone with interfaces needs a name of at most %d bytes", z, MaxZoneNameBytes)
			}
			idx[z] = sortedUnique(lits)
		}
	}
	return idx, nil
}

// clause matches keyword (iifname or oifname) against the interfaces of
// zones: "" when zones is empty, which matches every interface. matches is
// false when none of zones has an interface.
func (idx zoneIndex) clause(keyword string, zones []string) (clause string, matches bool) {
	if len(zones) == 0 {
		return "", true
	}
	var lits []string
	for _, z := range zones {
		lits = append(lits, idx[z]...)
	}
	if len(lits) == 0 {
		return "", false
	}
	return keyword + " { " + strings.Join(sortedUnique(lits), ", ") + " }", true
}

// unmatched returns zones, sorted, when it names zones and none of them has
// an interface, so that it matches no interface; nil otherwise.
func (idx zoneIndex) unmatched(zones []string) []string {
	if _, matches := idx.clause("", zones); matches {
		return nil
	}
	return sortedUnique(zones)
}

const zoneSetPrefix = "zone_"

// MaxZoneNameBytes is the longest zone name, in bytes, whose set name
// (zoneSetName) fits the kernel's 255-byte object names. Configuration
// validation refuses longer zone names with it.
const MaxZoneNameBytes = (255 - len(zoneSetPrefix)) / 2

// zoneSetName names the set of a zone's interfaces: zone_<hex name>. Hex
// keeps any zone name a valid nft identifier and distinct, so zones whose
// names differ only in case or punctuation get sets of their own.
func zoneSetName(zone string) string {
	return zoneSetPrefix + hex.EncodeToString([]byte(zone))
}

// writeSets declares the interface set of every zone that has interfaces,
// for local input and NAT rules.
func (idx zoneIndex) writeSets(buf *bytes.Buffer) {
	zones := make([]string, 0, len(idx))
	for z := range idx {
		zones = append(zones, z)
	}
	sort.Strings(zones)
	for _, z := range zones {
		fmt.Fprintf(buf, "  set %s {\n    type ifname;\n    elements = { %s }\n  }\n", zoneSetName(z), strings.Join(idx[z], ", "))
	}
}

// zoneWarnings reports the firewall rules whose source or destination
// zones have no interfaces: such a rule matches nothing.
func zoneWarnings(snap *rules.Snapshot, idx zoneIndex) []RuleWarning {
	var out []RuleWarning
	for _, e := range snap.Firewall {
		zones := sortedUnique(append(idx.unmatched(e.SourceZones), idx.unmatched(e.DestZones)...))
		if len(zones) == 0 {
			continue
		}
		named := "zone " + zones[0]
		if len(zones) > 1 {
			named = "zones " + strings.Join(zones, ", ")
		}
		out = append(out, RuleWarning{RuleID: e.ID, Predicate: PredicateZone, Zones: zones, Action: e.Action,
			Message: "no interface is assigned to " + named + "; the rule matches nothing until one is"})
	}
	return out
}

// chainTarget is the hook a firewall decision graph is lowered for. The
// forward chain sees both directions of a connection on the wire. A gated
// connection is terminated by the scanning gate: its original direction is
// delivered to the input hook and its replies leave through the output
// hook, and its egress zone, which routing decides, is recorded in the
// connection mark at selection (GateZoneCtMask) instead of being read from
// an output interface.
type chainTarget int

const (
	// targetForward lowers for the forward chain: ingress and egress zones
	// from the packet's interfaces, both directions.
	targetForward chainTarget = iota
	// targetGateInput lowers for the input-side gate chain: the original
	// direction only, ingress from the input interface, egress from the
	// connection mark.
	targetGateInput
	// targetGateReply lowers for the output-side gate chain: the reply
	// direction only, ingress (the original egress) from the connection
	// mark, egress from the output interface.
	targetGateReply
)

// zoneLowering lowers the zone predicates of rules for one target.
type zoneLowering struct {
	idx    zoneIndex
	target chainTarget
	// gate maps each egress zone the gate selection references to its
	// connection-mark index; gate targets match egress zones against it.
	gate map[string]uint8
}

// original returns the ingress and egress matches of the original
// direction of a connection in e's zones: "" matches any. matches is false
// when the zones can match no connection of the target.
func (z zoneLowering) original(e rules.Entry) (in, out string, matches bool) {
	in, inOK := z.idx.clause("iifname", e.SourceZones)
	out, outOK := z.egress(e.DestZones)
	return in, out, inOK && outOK
}

// egress matches the egress zones of a connection's original direction:
// the output interface for the forward chain, the connection-mark index
// for the gate targets. A gated connection can only have an index of the
// selection's egress zones, so a rule whose egress zones have none matches
// no gated connection.
func (z zoneLowering) egress(zones []string) (clause string, matches bool) {
	if z.target == targetForward {
		return z.idx.clause("oifname", zones)
	}
	if len(zones) == 0 {
		return "", true
	}
	var indices []uint8
	for _, name := range zones {
		if i, ok := z.gate[name]; ok {
			indices = append(indices, i)
		}
	}
	if len(indices) == 0 {
		return "", false
	}
	return gateZoneClause(indices), true
}

// ctDirection is the zone match of a connection's packets in one
// direction.
type ctDirection struct{ clause, in, out string }

// ctDirections matches e's zones for the packets of a connection the
// target sees: as written on the original direction, swapped on replies.
// Without zones, one match without a direction covers both. matches is
// false when the zones match no connection of the target.
func (z zoneLowering) ctDirections(e rules.Entry) (dirs []ctDirection, matches bool) {
	in, out, ok := z.original(e)
	if !ok {
		return nil, false
	}
	if in == "" && out == "" {
		return []ctDirection{{}}, true
	}
	original := ctDirection{"ct direction original", in, out}
	switch z.target {
	case targetGateInput:
		return []ctDirection{original}, true
	case targetGateReply:
		replyOut, _ := z.idx.clause("oifname", e.SourceZones)
		return []ctDirection{{"ct direction reply", out, replyOut}}, true
	}
	replyIn, _ := z.idx.clause("iifname", e.DestZones)
	replyOut, _ := z.idx.clause("oifname", e.SourceZones)
	return []ctDirection{original, {"ct direction reply", replyIn, replyOut}}, true
}
