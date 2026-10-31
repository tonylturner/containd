// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package enforce

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/markabi"
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

// iec104EnvelopeRules are the rules of IEC104EnvelopeChain: the marked
// queue rules when open, drop when closed.
func (c *Compiler) iec104EnvelopeRules(open bool) []string {
	if !open {
		return []string{"drop"}
	}
	return c.queueRules(EnvelopeMark | markabi.EnforceScopeMark)
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
