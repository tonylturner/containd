// SPDX-License-Identifier: Apache-2.0
package enforce

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/coverage"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Static inspection failures veto the whole transport scope before steering or
// retained admission. They never evaluate message, identity or time selectors.
func (c *Compiler) writeUninspectableChains(buf *bytes.Buffer, snap *rules.Snapshot) {
	for i, e := range snap.Firewall {
		if !uninspectable(snap, e) {
			continue
		}
		count := counterStmt(e.ID)
		if e.Log && c.NFLogGroup > 0 {
			count += fmt.Sprintf(" log prefix %q group %d", logPrefix(e.ID, rules.ActionDeny), c.NFLogGroup)
		}
		writeChain(buf, fmt.Sprintf("ics_uninspectable_%d", i), count, "goto deny_clean")
	}
}

func uninspectable(s *rules.Snapshot, e rules.Entry) bool {
	return e.ICS.Protocol != "" && e.Action.Decides() && !rules.MonitorICS(e, s.DPIMode) && rules.InspectionUnavailable(s.DPIEnabled, s.DPIICSProtocols, e.ICS.Protocol) != ""
}

func (c *Compiler) writeUninspectable(buf *bytes.Buffer, p *predicates, target chainTarget) error {
	for i, e := range p.snap.Firewall {
		if !uninspectable(p.snap, e) {
			continue
		}
		// Preserve the implicit decoder transport when no explicit port is named.
		if len(e.Protocols) == 0 {
			for _, port := range ics.DecoderPorts() {
				if port.Protocol == e.ICS.Protocol {
					name := "tcp"
					if port.Transport == ics.UDP {
						name = "udp"
					}
					e.Protocols = append(e.Protocols, rules.Protocol{Name: name, Port: strconv.Itoa(int(port.Port))})
				}
			}
		}
		lines, err := p.transportLines(target, e, true, fmt.Sprintf("goto ics_uninspectable_%d", i), false)
		if err != nil {
			return err
		}
		for _, line := range lines {
			fmt.Fprintln(buf, "    "+line+";")
		}
	}
	return nil
}

func inspectionWarnings(s *rules.Snapshot) []RuleWarning {
	var out []RuleWarning
	for _, e := range s.Firewall {
		if e.ICS.Protocol == "" || !e.Action.Decides() || rules.MonitorICS(e, s.DPIMode) {
			continue
		}
		var messages []string
		add := func(message string) { messages = append(messages, message) }
		if !s.DPIEnabled {
			add("DPI is off; this enforce rule drops its transport traffic until dataplane.dpiEnabled is enabled")
		}
		if on, set := s.DPIICSProtocols[e.ICS.Protocol]; set && !on {
			add(fmt.Sprintf("The %s decoder is off; this enforce rule drops its transport traffic until dataplane.dpiIcsProtocols.%s is enabled", e.ICS.Protocol, e.ICS.Protocol))
		}
		for _, x := range s.DPIExclusions {
			if coverage.ExclusionOverlaps(coverage.Exclusion{Value: x.Value, Type: x.Type}, e.Sources, e.Destinations) {
				add(fmt.Sprintf("DPI exclusion %s overlaps this enforce rule; it drops excluded transport traffic until the exclusion is removed or narrowed", x.Value))
			}
		}
		if len(messages) > 0 {
			out = append(out, RuleWarning{RuleID: e.ID, Action: e.Action, Predicate: PredicateInspection, Message: strings.Join(messages, "; ")})
		}
	}
	return out
}
