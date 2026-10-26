// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package enforce

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// containd reserves the skb-mark bits in EnvelopeMarkMask. EnvelopeMark
// within them means "steered to the queue by an IEC104 envelope rule"; the
// other mark bits are preserved.
const (
	EnvelopeMarkMask uint32 = 0x0f000000
	EnvelopeMark     uint32 = 0x01000000
)

// iec104Port is the only supported IEC104 server port.
const iec104Port = 2404

// IEC104EnvelopeChain is the regular chain every IEC104 envelope steering
// rule jumps to. It holds one rule: the marked queue verdict while the
// engine owns its queue, and drop otherwise. Switching
// replaces that one rule in a single nft transaction, so the ruleset never
// passes through a state where envelope traffic is neither queued to the
// engine nor dropped, and no other rule changes.
const IEC104EnvelopeChain = "iec104_envelope"

// EnvelopeMarked reports whether an NFQUEUE skb mark carries EnvelopeMark.
func EnvelopeMarked(mark uint32) bool {
	return mark&EnvelopeMarkMask == EnvelopeMark
}

// SteersIEC104 reports whether CompileFirewall steers IEC104 envelope
// traffic to the queue for snap: a queue is configured and at least one
// IEC104 rule's scope covers TCP port 2404.
func (c *Compiler) SteersIEC104(snap *rules.Snapshot) bool {
	if c.QueueID <= 0 || snap == nil {
		return false
	}
	for _, e := range snap.Firewall {
		if isIEC104Rule(e) && admitsIEC104Port(e.Protocols) {
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
// sorted by rule ID. Each rule's session scope (opener -> server port 2404)
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
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
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

// iec104EnvelopeVerdict is the one rule of IEC104EnvelopeChain: the marked
// queue verdict when open, drop when closed.
func (c *Compiler) iec104EnvelopeVerdict(open bool) string {
	if !open {
		return "drop"
	}
	return fmt.Sprintf("meta mark set meta mark and 0x%08x or 0x%08x queue num %d",
		^EnvelopeMarkMask, EnvelopeMark, c.QueueID)
}

// writeIEC104EnvelopeChain emits IEC104EnvelopeChain in the state of
// c.IEC104EnvelopeOpen.
func (c *Compiler) writeIEC104EnvelopeChain(buf *bytes.Buffer) {
	buf.WriteString("  chain " + IEC104EnvelopeChain + " {\n")
	buf.WriteString("    " + c.iec104EnvelopeVerdict(c.IEC104EnvelopeOpen) + ";\n")
	buf.WriteString("  }\n")
}

// IEC104EnvelopeSwitch returns the nft script that sets the envelope state
// of an installed ruleset: one transaction that replaces the single rule of
// IEC104EnvelopeChain. Apply it only to a ruleset compiled for a snapshot
// that SteersIEC104.
func (c *Compiler) IEC104EnvelopeSwitch(open bool) string {
	table := c.policyTable()
	return fmt.Sprintf("flush chain inet %s %s\nadd rule inet %s %s %s\n",
		table, IEC104EnvelopeChain, table, IEC104EnvelopeChain, c.iec104EnvelopeVerdict(open))
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
	verdict := counterStmt(e.ID) + " jump " + IEC104EnvelopeChain
	port := strconv.Itoa(iec104Port)
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
		if lo, hi, ok := parsePortRange(p.Port); ok && lo <= iec104Port && iec104Port <= hi {
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
