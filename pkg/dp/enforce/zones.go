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
			if len(z) > maxZoneName {
				return nil, fmt.Errorf("zone %q: a zone with interfaces needs a name of at most %d bytes", z, maxZoneName)
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

// maxZoneName is the longest zone name, in bytes, whose set name fits the
// kernel's 255-byte object names.
const maxZoneName = (255 - len(zoneSetPrefix)) / 2

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

// ctDirection is the zone match of a connection's packets in one
// direction.
type ctDirection struct{ clause, in, out string }

// ctDirections matches e's zones for the packets of both directions of a
// connection: as written on the original direction, swapped on replies.
// Without zones, one match without a direction covers both. matches is
// false when the zones match no interface.
func (idx zoneIndex) ctDirections(e rules.Entry) (dirs []ctDirection, matches bool) {
	in, inOK := idx.clause("iifname", e.SourceZones)
	out, outOK := idx.clause("oifname", e.DestZones)
	if !inOK || !outOK {
		return nil, false
	}
	if in == "" && out == "" {
		return []ctDirection{{}}, true
	}
	replyIn, _ := idx.clause("iifname", e.DestZones)
	replyOut, _ := idx.clause("oifname", e.SourceZones)
	return []ctDirection{
		{"ct direction original", in, out},
		{"ct direction reply", replyIn, replyOut},
	}, true
}
