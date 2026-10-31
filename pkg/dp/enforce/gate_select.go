// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// writeGateSelectChain emits gateSelectChain, the classification of a new
// connection's first SYN after DNAT, and reports whether it selects
// anything. Exclusions win: an excluded connection returns unmarked.
// An include entry marks the connection gated with the index of its egress
// zone, which routing decides; the first matching entry decides. A selected
// connection whose upstream leg today's source NAT would masquerade (an
// egress in the masquerade set, or a port forward's return path) is marked
// for the masquerading listener. Nothing here counts or logs: a
// classification is not a policy decision.
//
// IPv6 link-local endpoints are never selected: a transparent socket
// cannot bind a link-local address without its scope.
func writeGateSelectChain(buf *bytes.Buffer, snap *rules.Snapshot, zones zoneIndex) (selecting bool, err error) {
	gate := snap.Gate
	if !gate.Enabled {
		return false, nil
	}
	var lines []string
	for _, e := range gate.Exclude {
		line, err := gateExcludeLine(e)
		if err != nil {
			return false, err
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	zoneByName := make(map[string]rules.GateZone, len(gate.Zones))
	for _, z := range gate.Zones {
		zoneByName[z.Name] = z
	}
	var includes []string
	for _, e := range gate.Include {
		entry, err := gateIncludeLines(e, zoneByName)
		if err != nil {
			return false, err
		}
		includes = append(includes, entry...)
	}
	if len(includes) == 0 {
		return false, nil
	}
	lines = append(lines, includes...)
	masq, err := gateMasqueradeLines(snap, zones)
	if err != nil {
		return false, err
	}
	lines = append(lines, masq...)
	buf.WriteString("  chain " + gateSelectChain + " {\n")
	buf.WriteString("    ip6 saddr fe80::/10 return;\n")
	buf.WriteString("    ip6 daddr fe80::/10 return;\n")
	for _, l := range lines {
		buf.WriteString("    " + l + ";\n")
	}
	buf.WriteString("    " + ctMarkMatch(GateCtMark, GateCtMark) + " goto " + GateAdmitChain + ";\n")
	buf.WriteString("  }\n")
	return true, nil
}

// gateExcludeLine lowers one exclude entry: every populated field must
// match. An entry constrained to nothing would exclude everything and is
// refused. "" is an entry that can match nothing.
func gateExcludeLine(e rules.GateEntry) (string, error) {
	parts, ports, err := gateEntryMatch(e)
	if err != nil {
		return "", err
	}
	if parts == nil {
		return "", nil
	}
	if ports != "" {
		parts = append(parts, ports)
	}
	if len(parts) == 0 {
		return "", errors.New("gate exclude entry without constraints would exclude every connection")
	}
	return strings.Join(append(parts, "return"), " "), nil
}

// gateIncludeLines lowers one include entry: one line per egress zone that
// has devices, marking the connection with that zone's index. A line takes
// a connection not yet selected, so the first matching entry decides.
func gateIncludeLines(e rules.GateEntry, zones map[string]rules.GateZone) ([]string, error) {
	if len(e.DestZones) == 0 || len(e.Ports) == 0 {
		return nil, errors.New("gate include entry needs egress zones and destination ports")
	}
	if len(e.Sources) > 0 || len(e.Destinations) > 0 || len(e.DestDevices) > 0 {
		return nil, errors.New("gate include entry carries exclude-only constraints")
	}
	parts, ports, err := gateEntryMatch(e)
	if err != nil {
		return nil, err
	}
	if parts == nil {
		return nil, nil
	}
	var out []string
	for _, name := range e.DestZones {
		z, ok := zones[name]
		if !ok {
			return nil, fmt.Errorf("gate include entry names egress zone %q, which the selection does not index", name)
		}
		if z.Index == 0 {
			return nil, fmt.Errorf("gate zone %q has index 0", name)
		}
		egress, err := gateDevices(z.Devices)
		if err != nil {
			return nil, fmt.Errorf("gate zone %q: %w", name, err)
		}
		if egress == "" {
			continue
		}
		line := append([]string{ctMarkMatch(GateCtMark, 0)}, parts...)
		line = append(line, "fib daddr oifname "+egress, ports, ctMarkSet(GateCtMark|uint32(z.Index)<<GateZoneCtShift))
		out = append(out, joinClauses(line))
	}
	return out, nil
}

// gateEntryMatch lowers the constraints an include and an exclude entry
// share: family, ingress devices, egress devices and addresses, in that
// order, and the port match apart ("" for any port). nil parts are an
// entry whose constraints match nothing (an address side without a prefix
// of the entry's family); empty, non-nil parts are an unconstrained entry.
func gateEntryMatch(e rules.GateEntry) (parts []string, ports string, err error) {
	parts = []string{}
	ip := ""
	switch e.Family {
	case 0:
		if len(e.Sources) > 0 || len(e.Destinations) > 0 {
			return nil, "", errors.New("gate entry with addresses needs an address family")
		}
	case 4:
		ip = familyKeyword[0]
		parts = append(parts, "meta nfproto ipv4")
	case 6:
		ip = familyKeyword[1]
		parts = append(parts, "meta nfproto ipv6")
	default:
		return nil, "", fmt.Errorf("gate entry: unknown address family %d", e.Family)
	}
	ingress, err := gateDevices(e.SourceDevices)
	if err != nil {
		return nil, "", fmt.Errorf("gate entry ingress devices: %w", err)
	}
	if ingress != "" {
		parts = append(parts, "iifname "+ingress)
	}
	egress, err := gateDevices(e.DestDevices)
	if err != nil {
		return nil, "", fmt.Errorf("gate entry egress devices: %w", err)
	}
	if egress != "" {
		parts = append(parts, "fib daddr oifname "+egress)
	}
	for _, side := range []struct {
		keyword string
		cidrs   []string
	}{{"saddr", e.Sources}, {"daddr", e.Destinations}} {
		if len(side.cidrs) == 0 {
			continue
		}
		prefixes, err := gatePrefixes(side.cidrs, e.Family)
		if err != nil {
			return nil, "", err
		}
		parts = append(parts, ip+" "+side.keyword+" { "+strings.Join(prefixes, ", ")+" }")
	}
	for _, r := range e.Ports {
		if r.Lo == 0 || r.Lo > r.Hi {
			return nil, "", fmt.Errorf("gate entry: invalid port range %d-%d", r.Lo, r.Hi)
		}
	}
	if len(e.Ports) > 0 {
		ports = "tcp dport " + gatePortSet(e.Ports)
	}
	return parts, ports, nil
}

// gatePrefixes validates cidrs as prefixes of family (4 or 6), sorted.
func gatePrefixes(cidrs []string, family uint8) ([]string, error) {
	split, err := splitFamilies(cidrs)
	if err != nil {
		return nil, fmt.Errorf("gate entry: %w", err)
	}
	f := 0
	if family == 6 {
		f = 1
	}
	if len(split[1-f]) > 0 {
		return nil, fmt.Errorf("gate entry: address %s is not IPv%d", split[1-f][0], family)
	}
	return sortedUnique(split[f]), nil
}

// gateMasqueradeLines marks a selected connection for the masquerading
// listener when the source NAT of the postrouting chain (nat.go) would
// masquerade it: its ingress zone is a NAT source zone and its egress the
// NAT egress zone, or it is a port forward's connection whose return path
// is masqueraded. Without NAT nothing is masqueraded.
func gateMasqueradeLines(snap *rules.Snapshot, zones zoneIndex) ([]string, error) {
	if !snap.NAT.Enabled || len(snap.ZoneIfaces) == 0 {
		return nil, nil
	}
	gated := ctMarkMatch(GateCtMark, GateCtMark)
	var out []string
	for _, id := range forwardIDs(snap) {
		for _, match := range forwardMatchClauses(snap.ForwardMatches[id], targetGateInput) {
			out = append(out, gated+" "+match+" "+ctMarkSet(GateMasqSelCtMark))
		}
	}
	egress, srcZones := natMasqueradeZones(snap)
	egressDevs, ok := zones.clause("fib daddr oifname", []string{egress})
	if !ok {
		return out, nil
	}
	for _, z := range srcZones {
		if len(snap.ZoneIfaces[z]) == 0 {
			continue
		}
		out = append(out, fmt.Sprintf("%s iifname @%s %s %s", gated, zoneSetName(z), egressDevs, ctMarkSet(GateMasqSelCtMark)))
	}
	return out, nil
}
