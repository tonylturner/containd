// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"

	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

const (
	enforceQueueChain = "ics_enforce_queue"
	monitorIECChain   = "iec104_monitor_queue"
)

func (c *Compiler) writeInspectionChains(buf *bytes.Buffer, snap *rules.Snapshot) {
	// The public envelope chain remains the sole fail-closed readiness
	// switch for enforcing IEC traffic.
	if c.SteersIEC104(snap) {
		c.writeIEC104EnvelopeChain(buf)
	}
	monitorGeneric, enforceGeneric, monitorIEC := false, false, false
	for _, e := range snap.Firewall {
		if !e.Action.Decides() || !isDPIEligible(e) {
			continue
		}
		monitor := rules.MonitorICS(e, snap.DPIMode)
		if isIEC104Rule(e) {
			monitorIEC = monitorIEC || monitor && admitsIEC104Port(e.Protocols)
		} else {
			monitorGeneric = monitorGeneric || monitor
			enforceGeneric = enforceGeneric || !monitor
		}
	}
	if monitorGeneric {
		c.writeICSQueueChain(buf)
	}
	if enforceGeneric {
		writeChain(buf, enforceQueueChain, c.queueRules(markabi.EnforceScopeMark)...)
	}
	if monitorIEC {
		writeChain(buf, monitorIECChain, c.queueRules(markabi.EnvelopeMark)...)
	}
}

// Steering owns only inspection, not permission. Enforcing scopes outrank
// monitoring scopes; within each class configured order chooses the single
// counter owner. Identity, schedule and message selectors cannot hide a
// transport scope from inspection.
func (c *Compiler) writeInspection(buf *bytes.Buffer, p *predicates, target chainTarget) error {
	if c.QueueID <= 0 {
		return nil
	}
	for _, monitor := range []bool{false, true} {
		for _, iec := range []bool{true, false} {
			for _, e := range p.snap.Firewall {
				if !e.Action.Decides() || !isDPIEligible(e) ||
					rules.MonitorICS(e, p.snap.DPIMode) != monitor || isIEC104Rule(e) != iec {
					continue
				}
				chain := enforceQueueChain
				if monitor {
					chain = ICSQueueChain
				}
				if iec {
					if !admitsIEC104Port(e.Protocols) {
						continue
					}
					e.Protocols = []rules.Protocol{{Name: "tcp", Port: "2404"}}
					chain = IEC104EnvelopeChain
					if monitor {
						chain = monitorIECChain
					}
				}
				lines, err := p.transportLines(target, e, true, counterStmt(e.ID)+" jump "+chain, !iec)
				if err != nil {
					return err
				}
				for _, l := range lines {
					buf.WriteString("    " + unobservedGuard + " " + l + ";\n")
				}
			}
		}
	}
	return nil
}
