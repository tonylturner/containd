// SPDX-License-Identifier: Apache-2.0
package enforce

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func (c *Compiler) writeManagementInput(b *bytes.Buffer) error {
	r := c.ManagementReservation
	if r == nil {
		return nil
	}
	dev, err := ifnameLiteral(r.Device)
	if err != nil {
		return fmt.Errorf("management reservation: %w", err)
	}
	fmt.Fprintf(b, "    iifname %s ip saddr { %s } ip daddr %s tcp dport %d accept;\n", dev, reservationSources(r), r.Local.Addr(), r.Port)
	return nil
}

func reservationSources(r *mgmtpath.Reservation) string {
	sources := make([]string, 0, len(r.Sources))
	for _, a := range r.Sources {
		sources = append(sources, a.String())
	}
	return strings.Join(sources, ", ")
}

// resolveLocalInput returns snap's local input rules in ID order, with each
// management listener's bindings resolved in this namespace. A listener
// that resolves to no interface is omitted, never left unconstrained.
func resolveLocalInput(snap *rules.Snapshot) ([]rules.LocalServiceRule, error) {
	locals := append([]rules.LocalServiceRule(nil), snap.LocalInput...)
	sort.Slice(locals, func(i, j int) bool { return locals[i].ID < locals[j].ID })
	out := locals[:0]
	for _, lr := range locals {
		if lr.RecoverUnbound {
			live, err := mgmtpath.Devices()
			if err != nil {
				return nil, fmt.Errorf("discover management bindings: %w", err)
			}
			lr.Ifaces, _ = mgmtpath.ResolveBindings(lr.Ifaces, lr.DeniedIfaces, live)
			if len(lr.Ifaces) == 0 {
				continue
			}
		}
		out = append(out, lr)
	}
	return out, nil
}

// managementExemptions returns the rules that let management traffic pass
// the revocation chain: requests to the reserved management listener, to
// the engine API path and to each management listener on the interfaces it
// serves, and their replies.
// They accept only within the dynamic table, so the policy table still
// decides the traffic; a revocation can never refuse management access
// from the management network.
func (c *Compiler) managementExemptions(locals []rules.LocalServiceRule) (input, output []string, err error) {
	if r := c.ManagementReservation; r != nil {
		dev, err := ifnameLiteral(r.Device)
		if err != nil {
			return nil, nil, fmt.Errorf("management reservation: %w", err)
		}
		input = append(input, fmt.Sprintf("iifname %s ip saddr { %s } ip daddr %s tcp dport %d accept", dev, reservationSources(r), r.Local.Addr(), r.Port))
		output = append(output, fmt.Sprintf("oifname %s ip saddr %s ip daddr { %s } tcp sport %d accept", dev, r.Local.Addr(), reservationSources(r), r.Port))
	}
	if p := c.EngineAPI; p != nil {
		match, reply, err := p.matches()
		if err != nil {
			return nil, nil, err
		}
		input = append(input, match+" accept")
		output = append(output, reply+" accept")
	}
	for _, lr := range locals {
		// Only management listeners carry RecoverUnbound.
		if !lr.RecoverUnbound {
			continue
		}
		if _, err := compileLocalInputRule(lr, nil); err != nil {
			return nil, nil, err
		}
		set, err := ifnameSet(lr.Ifaces)
		if err != nil {
			return nil, nil, fmt.Errorf("local input %s: %w", lr.ID, err)
		}
		proto := strings.ToLower(strings.TrimSpace(lr.Proto))
		input = append(input, fmt.Sprintf("iifname %s %s dport %d accept", set, proto, lr.Port))
		output = append(output, fmt.Sprintf("oifname %s %s sport %d accept", set, proto, lr.Port))
	}
	return input, output, nil
}

// ValidateManagementSnapshot runs before kernel application or snapshot swapping.
func ValidateManagementSnapshot(s *rules.Snapshot, r *mgmtpath.Reservation) error {
	if s == nil || r == nil {
		return nil
	}
	for i, p := range s.NAT.PortForwards {
		if r.DNATOverlaps(p.Enabled, p.Proto, p.ListenPort, s.ZoneIfaces[strings.TrimSpace(p.IngressZone)], p.AllowedSources) {
			return fmt.Errorf("nat.portForwards[%d] conflicts with reserved management path", i)
		}
	}
	return nil
}
