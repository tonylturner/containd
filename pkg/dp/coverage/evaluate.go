// SPDX-License-Identifier: Apache-2.0

package coverage

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

const modeEnforce = "enforce"

// Evaluate reports the static coverage of every firewall rule in snap that
// names an ICS protocol, in rule ID order. It depends only on its inputs.
func Evaluate(snap *rules.Snapshot, s Settings) []Rule {
	if snap == nil {
		return nil
	}
	var out []Rule
	for _, e := range snap.Firewall {
		if e.ICS.Protocol == "" {
			continue
		}
		out = append(out, evaluateEntry(e, s))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

func evaluateEntry(e rules.Entry, s Settings) Rule {
	protocol := strings.ToLower(strings.TrimSpace(e.ICS.Protocol))
	mode := rules.EffectiveMode(e.ICS.Mode, s.DPIMode)
	r := Rule{RuleID: e.ID, Protocol: protocol, Mode: mode, State: Enforcing}
	if mode != modeEnforce {
		r.State = Monitoring
	}
	iec := protocol == rules.ProtocolIEC104
	if mode == modeEnforce {
		if !s.Enforcement {
			r.Lower(Reason{Code: EnforcementDisabled, Message: "nftables enforcement is off, so nothing steers this rule's traffic to the engine"})
		}
		if s.QueueID == 0 {
			r.Lower(Reason{Code: NoInlinePath, Message: "dataplane.nfqueueGroup is 0: the engine only observes copies and cannot hold or drop a command"})
		}
	}
	// The IEC 104 envelope is inspected whatever the DPI master switch says.
	if !s.DPIEnabled && !iec {
		r.Lower(Reason{Code: DPIDisabled, Message: "DPI is switched off (dataplane.dpiEnabled), so no command of this rule is decoded"})
	}
	if on, set := s.ICSProtocols[protocol]; set && !on {
		r.Lower(Reason{Code: DecoderDisabled, Message: fmt.Sprintf("the %s decoder is switched off (dataplane.dpiIcsProtocols.%s)", protocol, protocol)})
	}
	// IEC 104 inspection ignores every DPI exclusion.
	if !iec {
		for _, x := range s.Exclusions {
			addExclusionReason(&r, e, x)
		}
	}
	return r
}

func addExclusionReason(r *Rule, e rules.Entry, x Exclusion) {
	switch {
	case x.Type == "domain":
		r.Lower(Reason{Code: DomainExclusion, Value: x.Value,
			Message: fmt.Sprintf("flows to addresses that DNS or TLS associate with %s skip inspection", x.Value)})
	case ExclusionOverlaps(x, e.Sources, e.Destinations):
		r.Lower(Reason{Code: ExclusionOverlap, Value: x.Value,
			Message: fmt.Sprintf("DPI exclusion %s meets this rule's addresses; its flows skip inspection", x.Value)})
	}
}

// Lower records reason and lowers the rule's state to what the reason
// allows: an exclusion leaves an enforcing rule partial, every other cause
// leaves it not enforcing. A monitoring rule keeps its state; the reason
// explains what it cannot observe.
func (r *Rule) Lower(reason Reason) {
	r.Reasons = append(r.Reasons, reason)
	if r.State == Monitoring || r.State == NotEnforcing {
		return
	}
	switch reason.Code {
	case ExclusionOverlap, DomainExclusion:
		r.State = Partial
	default:
		r.State = NotEnforcing
	}
}

// ExclusionOverlaps reports whether an IP or CIDR exclusion can match a flow
// of a rule whose L3 scope is sources and destinations. The engine checks
// both endpoints of a flow, so an exclusion overlaps when it meets either
// side. An empty side matches any address, and an entry that is not an
// address or CIDR (a VPN token resolved elsewhere) counts as overlapping.
// Domain exclusions and unparseable values never overlap.
func ExclusionOverlaps(x Exclusion, sources, destinations []string) bool {
	var excl *net.IPNet
	switch x.Type {
	case "ip":
		excl = hostNet(strings.TrimSpace(x.Value))
	case "cidr":
		_, n, err := net.ParseCIDR(strings.TrimSpace(x.Value))
		if err == nil {
			excl = n
		}
	}
	if excl == nil {
		return false
	}
	return sideOverlaps(sources, excl) || sideOverlaps(destinations, excl)
}

func sideOverlaps(side []string, excl *net.IPNet) bool {
	if len(side) == 0 {
		return true
	}
	for _, s := range side {
		s = strings.TrimSpace(s)
		n := hostNet(s)
		if n == nil {
			_, c, err := net.ParseCIDR(s)
			if err != nil {
				return true
			}
			n = c
		}
		if n.Contains(excl.IP) || excl.Contains(n.IP) {
			return true
		}
	}
	return false
}

// hostNet is the single-address network of ip, or nil if it is not an
// address.
func hostNet(ip string) *net.IPNet {
	addr := net.ParseIP(ip)
	if addr == nil {
		return nil
	}
	if v4 := addr.To4(); v4 != nil {
		addr = v4
	}
	bits := 8 * len(addr)
	return &net.IPNet{IP: addr, Mask: net.CIDRMask(bits, bits)}
}
