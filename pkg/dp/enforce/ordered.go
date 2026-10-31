// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

var nonAdmitGuard = fmt.Sprintf("meta mark & 0x%08x != 0", markabi.NonAdmitMark)

func writeChain(buf *bytes.Buffer, name string, lines ...string) {
	fmt.Fprintln(buf, "  chain "+name+" {")
	for _, line := range lines {
		fmt.Fprintln(buf, "    "+line+";")
	}
	fmt.Fprintln(buf, "  }")
}

// All policy exits preserve unrelated skb/ct bits. Invalid/untracked
// admissions use the same exits but never read or stamp conntrack marks.
func (c *Compiler) writeAdmissionChains(buf *bytes.Buffer, parity uint32) {
	clean := fmt.Sprintf("meta mark set meta mark & 0x%08x", ^markabi.ContinuationSkbMask)
	writeChain(buf, "deny_clean", clean, "drop")
	writeChain(buf, "reset_tcp_clean", clean, rejectTCP)
	writeChain(buf, "reset_other_clean", clean, rejectOther)
	for _, name := range []string{"admit_clean", "related_clean"} {
		writeChain(buf, name, nonAdmitGuard+" goto deny_clean", clean, "accept")
	}
	writeChain(buf, "admit_unconditional", nonAdmitGuard+" goto deny_clean",
		fmt.Sprintf("%s ct mark set (ct mark & 0x%08x) | 0x%08x", trackedState, ^markabi.AdmissionCtMask, markabi.AdmittedBit|parity),
		"goto admit_clean")
	writeChain(buf, "admit_conditional", nonAdmitGuard+" goto deny_clean",
		fmt.Sprintf("%s ct mark set ct mark & 0x%08x", trackedState, ^markabi.AdmittedBit),
		"goto admit_clean")
}

// transportLines uses original-client/backend coordinates for tracked
// packets, and only trustworthy packet headers without conntrack.
func (p *predicates) transportLines(target chainTarget, e rules.Entry, scope bool, tail string, originalOnly bool) ([]string, error) {
	alts := []alternative{{family: familyAny}}
	var err error
	if !scope {
		alts, err = p.alternatives(e, true)
		if err != nil {
			return nil, err
		}
	}
	lines, err := p.ctLines(target, e, alts, tail, originalOnly)
	if err != nil {
		return nil, err
	}
	for i := range lines {
		lines[i] = trackedState + " " + lines[i]
	}
	if target != targetForward || len(e.ViaForwards) != 0 {
		return lines, nil
	}
	header := e
	if queuedToEngine(e, p.queueID) {
		header.Action = rules.ActionAllow
	}
	header.ICS = rules.ICSPredicate{}
	if scope {
		header.Identities, header.Schedule = nil, rules.SchedulePredicate{}
	}
	raw, err := headerLines(header, p.lowering(target), tail)
	if err != nil {
		return nil, err
	}
	fallback, err := p.guard(header, raw)
	if err != nil {
		return nil, err
	}
	for _, l := range fallback {
		lines = append(lines, untrackedState+" "+l)
	}
	return lines, nil
}

func (c *Compiler) writeOrderedChains(buf *bytes.Buffer, p *predicates, target chainTarget) error {
	_, name := target.recheckChains()
	var body []string
	for i, e := range p.snap.Firewall {
		if !e.Action.Decides() || rules.MonitorICS(e, p.snap.DPIMode) {
			continue
		}
		decision := fmt.Sprintf("%s_rule_%d", name, i)
		c.writeTerminalChain(buf, decision, e, p.snap.AdmissionParity)
		lines, err := p.transportLines(target, e, false, "goto "+decision, false)
		if err != nil {
			return err
		}
		body = append(body, lines...)
	}
	tail := "goto deny_clean"
	if p.snap.Default == rules.ActionAllow {
		tail = "goto admit_unconditional"
	}
	writeChain(buf, name, append(body, tail)...)
	return p.writeRecheckChains(buf, target)
}

func (c *Compiler) writeTerminalChain(buf *bytes.Buffer, name string, e rules.Entry, parity uint32) {
	admitting := e.Action == rules.ActionAllow || queuedToEngine(e, c.QueueID)
	var lines []string
	// ICS counters measure selected steering, not transport admission.
	if !queuedToEngine(e, c.QueueID) {
		count := counterStmt(e.ID)
		if e.Log && c.NFLogGroup > 0 {
			count += fmt.Sprintf(" log prefix %q group %d", logPrefix(e.ID, e.Action), c.NFLogGroup)
		}
		if admitting {
			lines = append(lines, nonAdmitGuard+" goto deny_clean",
				untrackedState+" "+count,
				fmt.Sprintf("%s ct mark & 0x%08x == 0 %s", trackedState, markabi.OwnedForwardCtBit, count),
				fmt.Sprintf("%s ct mark & 0x%08x != 0 ct mark & 0x%08x != 0x%08x %s",
					trackedState, markabi.OwnedForwardCtBit, markabi.AdmissionCtMask, markabi.AdmittedBit|parity, count))
		} else {
			lines = append(lines, count)
		}
	}
	if admitting {
		exit := "admit_unconditional"
		if conditional(e) {
			exit = "admit_conditional"
		}
		lines = append(lines, "goto "+exit)
	} else if e.Action == rules.ActionReset {
		lines = append(lines, "meta l4proto tcp goto reset_tcp_clean", "goto reset_other_clean")
	} else {
		lines = append(lines, "goto deny_clean")
	}
	writeChain(buf, name, lines...)
}
