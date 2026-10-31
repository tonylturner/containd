// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Hex is injective even for non-ASCII interface names, and remains well
// below the nft object-name limit for every valid Linux device name.
func localAddressSet(device string) string { return "local4_" + hex.EncodeToString([]byte(device)) }

func localAddresses(device string, addrs []netip.Addr) ([]string, error) {
	if err := ValidateInterfaceName(device); err != nil {
		return nil, err
	}
	var elems []string
	for _, addr := range addrs {
		if !addr.Is4() {
			return nil, fmt.Errorf("device %s: local address %s is not IPv4", device, addr)
		}
		elems = append(elems, addr.String())
	}
	return sortedUnique(elems), nil
}

// LocalAddressUpdate replaces only elements, atomically, never hooks or
// policy tables. The engine applies this script and publishes its matching
// resolver snapshot under its policy publication barrier.
func (c *Compiler) LocalAddressUpdate(device string, addrs []netip.Addr) (string, error) {
	if err := ValidateTableName(c.DynamicTable()); err != nil {
		return "", err
	}
	elems, err := localAddresses(device, addrs)
	if err != nil {
		return "", err
	}
	name := localAddressSet(device)
	script := fmt.Sprintf("flush set inet %s %s\n", c.policyTable(), name)
	if len(elems) != 0 {
		script += fmt.Sprintf("add element inet %s %s { %s }\n", c.policyTable(), name, strings.Join(elems, ", "))
	}
	return script, nil
}

func writeLocalAddressSets(buf *bytes.Buffer, snap *rules.Snapshot) error {
	var devices []string
	for dev := range snap.LocalIPv4ByDevice {
		devices = append(devices, dev)
	}
	for _, f := range snap.ForwardMatches {
		if f.ListenAddress.IsValid() && !f.ListenAddress.Is4() {
			return fmt.Errorf("forward listen address %s is not IPv4", f.ListenAddress)
		}
		for _, src := range f.AllowedSources {
			if !src.IsValid() || !src.Addr().Is4() {
				return fmt.Errorf("forward source %s is not IPv4", src)
			}
		}
		devices = append(devices, f.IngressDevices...)
	}
	for _, dev := range sortedUnique(devices) {
		elems, err := localAddresses(dev, snap.LocalIPv4ByDevice[dev])
		if err != nil {
			return err
		}
		fmt.Fprintf(buf, "  set %s {\n    type ipv4_addr;\n", localAddressSet(dev))
		if len(elems) != 0 {
			fmt.Fprintf(buf, "    elements = { %s }\n", strings.Join(elems, ", "))
		}
		fmt.Fprintln(buf, "  }")
	}
	return nil
}

func forwardIDs(snap *rules.Snapshot) []string {
	var ids []string
	for id := range snap.ForwardMatches {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func activeForward(f rules.ForwardMatch) bool {
	return f.Enabled && len(f.IngressDevices) > 0 && (f.Protocol == "tcp" || f.Protocol == "udp") &&
		f.ListenPort != 0 && f.Backend.IsValid() && f.Backend.Addr().Is4() && f.Backend.Port() != 0
}

func publicDestination(f rules.ForwardMatch, device, keyword string) string {
	if f.ListenAddress.IsValid() {
		return keyword + " " + f.ListenAddress.String()
	}
	return keyword + " @" + localAddressSet(device)
}

func forwardSources(f rules.ForwardMatch, keyword string) string {
	if len(f.AllowedSources) == 0 {
		return ""
	}
	var sources []string
	for _, src := range f.AllowedSources {
		sources = append(sources, src.Masked().String())
	}
	return keyword + " { " + strings.Join(sortedUnique(sources), ", ") + " }"
}

// forwardMatchClauses is the one expansion used by via, return SNAT and
// gate masquerade. Reply packets expose the original ingress as oifname.
func forwardMatchClauses(f rules.ForwardMatch, target chainTarget) []string {
	if !activeForward(f) {
		return nil
	}
	var out []string
	for _, dev := range sortedUnique(f.IngressDevices) {
		// All devices were validated while declaring their address sets.
		lit := strconv.Quote(dev)
		tuple := joinClauses([]string{
			fmt.Sprintf("ct mark & 0x%08x != 0", markabi.OwnedForwardCtBit),
			"meta l4proto " + f.Protocol,
			fmt.Sprintf("ct original proto-dst %d", f.ListenPort),
			publicDestination(f, dev, "ct original ip daddr"),
			forwardSources(f, "ct original ip saddr"),
			"ct reply ip saddr " + f.Backend.Addr().String(),
			fmt.Sprintf("ct reply proto-src %d", f.Backend.Port()),
		})
		if target != targetGateReply {
			out = append(out, "ct direction original iifname "+lit+" "+tuple)
		}
		if target != targetGateInput {
			out = append(out, "ct direction reply oifname "+lit+" "+tuple)
		}
	}
	return out
}

func forwardClauses(snap *rules.Snapshot, e rules.Entry, target chainTarget) []string {
	if len(e.ViaForwards) == 0 {
		return []string{""}
	}
	var out []string
	for _, id := range sortedUnique(e.ViaForwards) {
		out = append(out, forwardMatchClauses(snap.ForwardMatches[id], target)...)
	}
	return out
}

func forwardWarnings(snap *rules.Snapshot) []RuleWarning {
	var out []RuleWarning
	for _, e := range snap.Firewall {
		if len(e.ViaForwards) == 0 {
			continue
		}
		possible := func(id string) bool {
			f := snap.ForwardMatches[id]
			if !activeForward(f) {
				return false
			}
			if len(e.SourceZones) == 0 {
				return true
			}
			for _, zone := range e.SourceZones {
				for _, dev := range snap.ZoneIfaces[zone] {
					if slices.Contains(f.IngressDevices, dev) {
						return true
					}
				}
			}
			return false
		}
		if !slices.ContainsFunc(e.ViaForwards, possible) {
			out = append(out, RuleWarning{RuleID: e.ID, Action: e.Action, Predicate: PredicateForward,
				Message: "no referenced forward is enabled and bound in the rule's source zones; the rule matches nothing"})
		}
	}
	return out
}
