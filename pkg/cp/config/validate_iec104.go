// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"fmt"
	"net"
	"slices"
	"strings"
)

// IEC 60870-5-104 predicate limits.
const (
	iec104MaxCA  = 65534    // 65535 is the broadcast address; never allowed by policy
	iec104MaxIOA = 16777215 // 24-bit information object address
)

var iec104Classes = []string{"monitor", "control", "system", "unknown"}

// iec104DescribedTypes are the Type IDs with a decoder descriptor.
// An enforce ALLOW rule may name only these; types without a
// descriptor decode as unsupported and may appear in deny or learn rules.
var iec104DescribedTypes = map[int]struct{}{
	1: {}, 3: {}, 5: {}, 7: {}, 9: {}, 11: {}, 13: {}, 15: {}, 21: {},
	30: {}, 31: {}, 32: {}, 33: {}, 34: {}, 35: {}, 36: {}, 37: {},
	45: {}, 46: {}, 47: {}, 48: {}, 49: {}, 50: {}, 51: {},
	58: {}, 59: {}, 60: {}, 61: {}, 62: {}, 63: {}, 64: {},
	70: {}, 100: {}, 101: {}, 102: {}, 103: {}, 105: {}, 107: {},
}

// validateIEC104Predicate checks the fields of one iec104 predicate.
// Generic fields are rejected when set at all; JSON decoding already
// rejects them by presence.
func validateIEC104Predicate(p ICSPredicate, ruleID string) error {
	switch {
	case p.FunctionCode != nil:
		return fmt.Errorf("rule %s ics functionCode is not supported for protocol iec104; use typeIds", ruleID)
	case p.UnitID != nil:
		return fmt.Errorf("rule %s ics unitId is not supported for protocol iec104; use ca", ruleID)
	case p.Addresses != nil:
		return fmt.Errorf("rule %s ics addresses is not supported for protocol iec104; use ioa", ruleID)
	case p.ObjectClasses != nil:
		return fmt.Errorf("rule %s ics objectClasses is not supported for protocol iec104", ruleID)
	case p.WriteOnly:
		return fmt.Errorf("rule %s ics writeOnly is not supported for protocol iec104", ruleID)
	}
	if err := validateIEC104TypeIDs(p.TypeIDs, ruleID); err != nil {
		return err
	}
	if err := validateIEC104Classes(p.Classes, ruleID); err != nil {
		return err
	}
	if err := validateIEC104CA(p.CA, ruleID); err != nil {
		return err
	}
	return validateIEC104IOA(p.IOA, ruleID)
}

func validateIEC104TypeIDs(ids []int, ruleID string) error {
	if ids != nil && len(ids) == 0 {
		return fmt.Errorf("rule %s ics typeIds must not be empty; omit it to match any type", ruleID)
	}
	for _, id := range ids {
		if id < 1 || id > 255 {
			return fmt.Errorf("rule %s ics typeIds value %d out of range 1..255", ruleID, id)
		}
	}
	return nil
}

func validateIEC104Classes(classes []string, ruleID string) error {
	if classes != nil && len(classes) == 0 {
		return fmt.Errorf("rule %s ics classes must not be empty; omit it to match any class", ruleID)
	}
	for _, c := range classes {
		if !slices.Contains(iec104Classes, c) {
			return fmt.Errorf("rule %s ics classes value %q invalid (want %s)", ruleID, c, strings.Join(iec104Classes, ", "))
		}
	}
	return nil
}

func validateIEC104CA(cas []uint16, ruleID string) error {
	if cas != nil && len(cas) == 0 {
		return fmt.Errorf("rule %s ics ca must not be empty; omit it to match any common address", ruleID)
	}
	for _, ca := range cas {
		if ca > iec104MaxCA {
			return fmt.Errorf("rule %s ics ca %d is the broadcast address; rules cannot name it", ruleID, ca)
		}
	}
	return nil
}

func validateIEC104IOA(ranges []IOARange, ruleID string) error {
	if ranges != nil && len(ranges) == 0 {
		return fmt.Errorf("rule %s ics ioa must not be empty; omit it to match any address", ruleID)
	}
	for _, r := range ranges {
		if r.End > iec104MaxIOA {
			return fmt.Errorf("rule %s ics ioa end %d out of range 0..%d", ruleID, r.End, iec104MaxIOA)
		}
		if r.Start > r.End {
			return fmt.Errorf("rule %s ics ioa range %d-%d has start after end", ruleID, r.Start, r.End)
		}
	}
	sorted := slices.Clone(ranges)
	slices.SortFunc(sorted, func(a, b IOARange) int { return int(a.Start) - int(b.Start) })
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Start <= sorted[i-1].End {
			return fmt.Errorf("rule %s ics ioa ranges %d-%d and %d-%d overlap", ruleID,
				sorted[i-1].Start, sorted[i-1].End, sorted[i].Start, sorted[i].End)
		}
	}
	return nil
}

// effectiveICSMode resolves a rule's ICS mode the way the engine does:
// rule mode > global dpiMode > learn.
func effectiveICSMode(ruleMode, globalMode string) string {
	if m := strings.ToLower(strings.TrimSpace(ruleMode)); m != "" {
		return m
	}
	if m := strings.ToLower(strings.TrimSpace(globalMode)); m != "" {
		return m
	}
	return "learn"
}

// validateIEC104Policy checks what needs the whole config: which types an
// ALLOW rule may name, and the static causes that keep an IEC104 enforce
// envelope from activating. Commit, candidate and import all
// validate, so these reject the config before it is saved.
func validateIEC104Policy(c *Config) error {
	var enforce []Rule
	for _, r := range c.Firewall.Rules {
		if r.ICS.Protocol != ICSProtocolIEC104 {
			continue
		}
		mode := effectiveICSMode(r.ICS.Mode, c.DataPlane.DPIMode)
		if r.Action == ActionAllow && mode != "learn" {
			if err := validateIEC104AllowTypes(r); err != nil {
				return err
			}
		}
		if mode == "enforce" {
			enforce = append(enforce, r)
		}
	}
	if len(enforce) == 0 {
		return nil
	}
	return validateIEC104Activation(c.DataPlane, enforce)
}

func validateIEC104AllowTypes(r Rule) error {
	for _, id := range r.ICS.TypeIDs {
		if _, ok := iec104DescribedTypes[id]; !ok {
			return fmt.Errorf("rule %s ics typeIds value %d has no IEC104 descriptor; an enforce ALLOW rule cannot name it", r.ID, id)
		}
	}
	if slices.Contains(r.ICS.Classes, "unknown") {
		return fmt.Errorf("rule %s ics classes \"unknown\" cannot be allowed in enforce mode", r.ID)
	}
	return nil
}

func validateIEC104Activation(dp DataPlaneConfig, enforce []Rule) error {
	first := enforce[0].ID
	if !dp.DPIEnabled {
		return fmt.Errorf("rule %s: iec104 enforce needs dataplane.dpiEnabled", first)
	}
	if on, set := dp.DPIICSProtocols[ICSProtocolIEC104]; set && !on {
		return fmt.Errorf("rule %s: iec104 enforce needs the iec104 decoder; dataplane.dpiIcsProtocols.iec104 is false", first)
	}
	// A zero nfqueueGroup means the engine captures with AF_PACKET, which
	// observes but cannot hold or drop a packet.
	if dp.NFQueueGroup == 0 {
		return fmt.Errorf("rule %s: iec104 enforce needs NFQUEUE capture; set dataplane.nfqueueGroup to a non-zero queue", first)
	}
	for _, r := range enforce {
		for _, excl := range dp.DPIExclusions {
			if dpiExclusionOverlapsRule(excl, r) {
				return fmt.Errorf("rule %s: dpi exclusion %q overlaps the iec104 enforce envelope", r.ID, excl.Value)
			}
		}
	}
	return nil
}

// dpiExclusionOverlapsRule reports whether an IP or CIDR exclusion can
// match a flow of the rule's L3 scope. The engine checks both endpoints of
// a flow, so an exclusion overlaps when it meets either side. An empty side
// matches any address. VPN tokens resolve elsewhere, so they count as
// overlapping. Domain exclusions cannot bypass IEC104 inspection: the engine
// keeps port 2404 and its enforcement envelope inspected regardless of DNS/SNI.
func dpiExclusionOverlapsRule(excl DPIExclusion, r Rule) bool {
	var exclNet *net.IPNet
	switch excl.Type {
	case "domain":
		return false
	case "ip":
		ip := net.ParseIP(strings.TrimSpace(excl.Value))
		if ip == nil {
			return false
		}
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		}
		bits := 8 * len(ip)
		exclNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	case "cidr":
		_, n, err := net.ParseCIDR(strings.TrimSpace(excl.Value))
		if err != nil {
			return false
		}
		exclNet = n
	default:
		return false
	}
	return cidrsOverlap(r.Sources, exclNet) || cidrsOverlap(r.Destinations, exclNet)
}

func cidrsOverlap(side []string, n *net.IPNet) bool {
	if len(side) == 0 {
		return true
	}
	for _, s := range side {
		if isSpecialCIDRToken(s) {
			return true
		}
		if _, c, err := net.ParseCIDR(s); err == nil && cidrOverlap(c, n) {
			return true
		}
	}
	return false
}
