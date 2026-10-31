// SPDX-License-Identifier: Apache-2.0
package config

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// ForwardTraffic describes the entire selector that receives no synthesized
// permission. It is not a claim that current policy denies all of this traffic.
// Backend zones are deliberately unknown: interface subnets cannot prove the
// actual routed egress of a packet, especially with policy routing.
type ForwardTraffic struct {
	Sources       []string `json:"sources"`
	IngressZone   string   `json:"ingressZone"`
	BackendZones  string   `json:"backendZones"`
	Protocol      string   `json:"protocol"`
	Backend       string   `json:"backend"`
	ListenAddress string   `json:"listenAddress"`
	ListenPort    int      `json:"listenPort"`
}

type ForwardGrantWarning struct {
	ForwardID string         `json:"forwardId"`
	RuleIDs   []string       `json:"ruleIds"`
	Traffic   ForwardTraffic `json:"traffic"`
	Message   string         `json:"message"`
}

// ForwardPlacement is a detached authoring decision shared by upgrade and
// publish. Overlap is "inside", "partial" (including unknown), or "no-overlap".
// Rule is nil for referenced, inside and partial forwards. Otherwise
// insert *Rule at Index, before existing terminals, without reordering policy.
type ForwardPlacement struct {
	ForwardID string               `json:"forwardId"`
	Overlap   string               `json:"overlap"`
	Reason    string               `json:"reason"`
	RuleIDs   []string             `json:"ruleIds,omitempty"`
	Rule      *Rule                `json:"rule,omitempty"`
	Index     int                  `json:"index"`
	Warning   *ForwardGrantWarning `json:"warning,omitempty"`
}

// ForwardAllowPlacement never mutates cfg. The forward must already be present
// in cfg when publishing, so references and ID collisions can be checked.
// Unknown scope intersections fail closed only for this generated grant;
// existing ICS rules, defaults and all other forwards are left alone.
func ForwardAllowPlacement(cfg *Config, forward PortForward) ForwardPlacement {
	p := ForwardPlacement{ForwardID: forward.ID, Overlap: "no-overlap"}
	inside := false
	for _, r := range cfg.Firewall.Rules {
		if !rules.Action(r.Action).Decides() || r.ICS.Protocol == "" ||
			rules.EffectiveMode(r.ICS.Mode, cfg.DataPlane.DPIMode) != "enforce" {
			continue
		}
		overlap, contains := forwardScopeOverlap(forward, r)
		if overlap {
			p.RuleIDs = append(p.RuleIDs, r.ID)
			inside = inside || contains
		}
	}
	slices.Sort(p.RuleIDs)
	if len(p.RuleIDs) > 0 {
		p.Overlap = "partial"
		if inside {
			p.Overlap = "inside"
		}
	}
	p.Reason = p.Overlap
	if p.Overlap == "partial" {
		traffic := forwardTraffic(forward)
		p.Warning = &ForwardGrantWarning{ForwardID: forward.ID, RuleIDs: slices.Clone(p.RuleIDs), Traffic: traffic,
			Message: fmt.Sprintf("Port forward %q overlaps enforcing ICS rules %v: no generated grant for sources %v, ingress zone %q, backend zones %s, protocol %s, backend service %s (public %s:%d). This includes traffic outside the inspected subset; current policy decides delivery. Existing inspection rules and defaults are unchanged.",
				forward.ID, p.RuleIDs, traffic.Sources, traffic.IngressZone, traffic.BackendZones, traffic.Protocol, traffic.Backend, traffic.ListenAddress, traffic.ListenPort)}
	}
	for _, r := range cfg.Firewall.Rules {
		if slices.Contains(r.ViaForwards, forward.ID) {
			p.Reason = "referenced"
			return p
		}
	}
	if p.Overlap != "no-overlap" {
		return p
	}
	p.Reason = "generated"
	r := ForwardAllowRule(cfg, forward.ID)
	p.Rule = &r
	// Leading grants retain stable forward-ID order, independent of colliding
	// generated rule IDs. Effects execute separately and need not be moved.
	for p.Index < len(cfg.Firewall.Rules) {
		old := cfg.Firewall.Rules[p.Index]
		if !rules.Action(old.Action).Decides() {
			p.Index++
			continue
		}
		if old.Action == ActionAllow && len(old.ViaForwards) == 1 && old.ViaForwards[0] < forward.ID {
			p.Index++
			continue
		}
		break
	}
	return p
}

// ForwardWarnings exposes current partial/unknown-overlap warnings without
// regenerating permissions on a current-schema document.
func ForwardWarnings(cfg *Config) []ForwardGrantWarning {
	var out []ForwardGrantWarning
	for _, f := range sortedForwards(cfg) {
		if p := ForwardAllowPlacement(cfg, f); f.Enabled && p.Warning != nil {
			out = append(out, *p.Warning)
		}
	}
	return out
}

func sortedForwards(cfg *Config) []PortForward {
	out := slices.Clone(cfg.Firewall.NAT.PortForwards)
	slices.SortFunc(out, func(a, b PortForward) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func forwardTraffic(f PortForward) ForwardTraffic {
	sources := slices.Clone(f.AllowedSources)
	if len(sources) == 0 {
		sources = []string{"0.0.0.0/0"}
	}
	port := f.DestPort
	if port == 0 {
		port = f.ListenPort
	}
	listen := f.ListenAddress
	if listen == "" {
		listen = "current ingress-device IPv4 addresses"
	}
	return ForwardTraffic{Sources: sources, IngressZone: f.IngressZone, BackendZones: "any routed egress (unknown)",
		Protocol: f.Proto, Backend: fmt.Sprintf("%s:%d", f.DestIP, port), ListenAddress: listen, ListenPort: f.ListenPort}
}

// forwardScopeOverlap proves disjointness or containment on independent
// transport dimensions. Anything unprovable remains partial; this is not a
// route resolver or a solver for complements of inspected traffic.
func forwardScopeOverlap(f PortForward, r Rule) (overlap, contains bool) {
	f.IngressZone = strings.TrimSpace(f.IngressZone)
	f.Proto = strings.ToLower(strings.TrimSpace(f.Proto))
	if len(r.SourceZones) > 0 && !slices.Contains(r.SourceZones, f.IngressZone) {
		return false, false
	}
	if len(r.ViaForwards) > 0 && !slices.Contains(r.ViaForwards, f.ID) {
		return false, false
	}
	port := f.DestPort
	if port == 0 {
		port = f.ListenPort
	}
	protocolCertain := true
	if len(r.Protocols) > 0 {
		matches, unknown := false, false
		for _, p := range r.Protocols {
			name := strings.ToLower(strings.TrimSpace(p.Name))
			if name != "tcp" && name != "udp" && name != "icmp" {
				unknown = true
				continue
			}
			if name != f.Proto {
				continue
			}
			if p.Port == "" {
				matches = true
				continue
			}
			lo, hi, err := rules.ParsePortRange(p.Port)
			unknown = unknown || err != nil
			matches = matches || err == nil && port >= int(lo) && port <= int(hi)
		}
		if !matches && !unknown {
			return false, false
		}
		protocolCertain = matches
	}
	destination := strings.TrimSpace(f.DestIP) + "/32"
	destOverlap, destContains := prefixIntersection([]string{destination}, r.Destinations)
	srcOverlap, srcContains := prefixIntersection(f.AllowedSources, r.Sources)
	if !destOverlap || !srcOverlap {
		return false, false
	}
	// Identity and schedule narrow admission, not the inspection union. They
	// cannot be used to prove that a forward is unconditionally contained.
	return true, protocolCertain && destContains && srcContains && len(r.DestZones) == 0 &&
		len(r.Identities) == 0 && r.Schedule == nil
}

func prefixIntersection(forward, scope []string) (overlap, contains bool) {
	if len(scope) == 0 {
		return true, true
	}
	if len(forward) == 0 {
		forward = []string{"0.0.0.0/0"}
	}
	contains = true
	for _, raw := range forward {
		f, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return true, false
		}
		covered := false
		for _, rawScope := range scope {
			s, err := netip.ParsePrefix(strings.TrimSpace(rawScope))
			if err != nil {
				// Includes unresolved VPN tokens and malformed historical rows.
				overlap = true
				continue
			}
			overlap = overlap || s.Overlaps(f)
			covered = covered || s.Bits() <= f.Bits() && s.Contains(f.Masked().Addr())
		}
		contains = contains && covered
	}
	return overlap, contains
}
