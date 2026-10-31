// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package enforce

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// IEC104EnvelopeChain is the regular chain every IEC104 envelope steering
// rule jumps to. While the engine owns its queue it queues every packet
// with EnvelopeMark, and HandshakeMark as the generic ICS queue does
// (queueRules); otherwise it holds one rule, drop. Switching flushes and
// refills the chain in a single nft transaction, so the ruleset never
// passes through a state where envelope traffic is neither queued to the
// engine nor dropped, and no other rule changes.
const IEC104EnvelopeChain = "iec104_envelope"

// SteersIEC104 reports whether CompileFirewall steers IEC104 envelope
// traffic to the queue for snap: a queue is configured and at least one
// IEC104 rule's scope covers TCP port 2404.
func (c *Compiler) SteersIEC104(snap *rules.Snapshot) bool {
	if c.QueueID <= 0 || snap == nil {
		return false
	}
	for _, e := range snap.Firewall {
		if isIEC104Rule(e) && !rules.MonitorICS(e, snap.DPIMode) && admitsIEC104Port(e.Protocols) {
			return true
		}
	}
	return false
}

// isIEC104Rule reports whether an entry carries an IEC104 semantic
// predicate. Its L3/L4 scope is part of the inspection envelope.
func isIEC104Rule(e rules.Entry) bool {
	return strings.EqualFold(strings.TrimSpace(e.ICS.Protocol), eventfields.ProtoIEC104)
}

// writeIEC104Steering emits the envelope steering of every IEC104 rule,
// enforcing scopes first, then monitor scopes, each sorted by rule ID.
// An overlapping monitor must not queue a packet without EnvelopeMark
// before an enforce scope can claim it, including packets with no trusted tuple.
// Each rule's session scope (opener -> server port 2404)
// jumps to IEC104EnvelopeChain in both directions, whatever the rule's
// action: the engine judges the content. These lines go before the
// conntrack established accept and every ordinary accept, so neither
// direction of an envelope session can bypass inspection.
func (c *Compiler) writeIEC104Steering(lines func(string), snap *rules.Snapshot, zones zoneIndex) error {
	entries := make([]rules.Entry, 0, len(snap.Firewall))
	for _, e := range snap.Firewall {
		if isIEC104Rule(e) && admitsIEC104Port(e.Protocols) {
			entries = append(entries, e)
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		left, right := rules.MonitorICS(entries[i], snap.DPIMode), rules.MonitorICS(entries[j], snap.DPIMode)
		if left != right {
			return !left
		}
		return entries[i].ID < entries[j].ID
	})
	for _, e := range entries {
		steering, err := compileIEC104Steering(e, zones)
		if err != nil {
			return err
		}
		for _, line := range steering {
			lines(line)
		}
	}
	return nil
}

// iec104EnvelopeRules are the rules of IEC104EnvelopeChain: the marked
// queue rules when open, drop when closed.
func (c *Compiler) iec104EnvelopeRules(open bool) []string {
	if !open {
		return []string{"drop"}
	}
	return c.queueRules(EnvelopeMark)
}

// writeIEC104EnvelopeChain emits IEC104EnvelopeChain in the state of
// c.IEC104EnvelopeOpen.
func (c *Compiler) writeIEC104EnvelopeChain(buf *bytes.Buffer) {
	buf.WriteString("  chain " + IEC104EnvelopeChain + " {\n")
	for _, rule := range c.iec104EnvelopeRules(c.IEC104EnvelopeOpen) {
		buf.WriteString("    " + rule + ";\n")
	}
	buf.WriteString("  }\n")
}

// IEC104EnvelopeSwitch returns the nft script that sets the envelope state
// of an installed ruleset: one transaction that flushes IEC104EnvelopeChain
// and adds the rules of the state. Apply it only to a ruleset compiled for
// a snapshot that SteersIEC104.
func (c *Compiler) IEC104EnvelopeSwitch(open bool) string {
	table := c.policyTable()
	var b strings.Builder
	fmt.Fprintf(&b, "flush chain inet %s %s\n", table, IEC104EnvelopeChain)
	for _, rule := range c.iec104EnvelopeRules(open) {
		fmt.Fprintf(&b, "add rule inet %s %s %s\n", table, IEC104EnvelopeChain, rule)
	}
	return b.String()
}

// compileIEC104Steering returns the client-to-server and server-to-client
// steering lines for one IEC104 rule, per address family, which count into
// the rule's counter. A rule that matches nothing has none.
func compileIEC104Steering(e rules.Entry, zones zoneIndex) ([]string, error) {
	scopes, err := addrScopes(e)
	if err != nil {
		return nil, err
	}
	in, inOK := zones.clause("iifname", e.SourceZones)
	out, outOK := zones.clause("oifname", e.DestZones)
	if !inOK || !outOK {
		return nil, nil
	}
	replyIn, _ := zones.clause("iifname", e.DestZones)
	replyOut, _ := zones.clause("oifname", e.SourceZones)
	chain := IEC104EnvelopeChain
	if rules.MonitorICS(e, "") {
		chain = ICSQueueChain
	}
	verdict := unobservedGuard + " " + counterStmt(e.ID) + " jump " + chain
	port := strconv.Itoa(ics.IEC104Port)
	var lines []string
	for _, s := range scopes {
		lines = append(lines,
			joinClauses(append(append([]string{in, out, "tcp dport " + port}, s.header(false)...), verdict)),
			joinClauses(append(append([]string{replyIn, replyOut, "tcp sport " + port}, s.header(true)...), verdict)))
	}
	return lines, nil
}

// admitsIEC104Port reports whether a rule's protocol list matches TCP
// destination port 2404, the session tuple the IEC104 envelope is
// evaluated on. No protocols matches everything.
func admitsIEC104Port(protos []rules.Protocol) bool {
	if len(protos) == 0 {
		return true
	}
	for _, p := range protos {
		if name := strings.ToLower(strings.TrimSpace(p.Name)); name != "" && name != "tcp" {
			continue
		}
		if p.Port == "" {
			return true
		}
		if lo, hi, ok := parsePortRange(p.Port); ok && lo <= ics.IEC104Port && ics.IEC104Port <= hi {
			return true
		}
	}
	return false
}

// parsePortRange parses "N" or "N-M" the way the rule evaluator does.
func parsePortRange(s string) (lo, hi uint64, ok bool) {
	l, h, err := rules.ParsePortRange(s)
	return uint64(l), uint64(h), err == nil
}
