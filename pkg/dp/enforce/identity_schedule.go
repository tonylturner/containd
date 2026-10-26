// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Identity and schedule predicates are conditional: what they admit changes
// without a new connection, when a binding is removed or a window opens or
// ends. nftables decides them on every rule it decides itself; rules queued
// to the engine keep their unconditional queue line and the engine decides
// their predicates per message.
//
// The conntrack fast path would otherwise keep an established connection
// that a conditional rule no longer admits, so established packets in the
// L3/L4 scope of a conditional rule are decided again, in both directions,
// before that accept (conditionalScopeChain): the connection keeps passing
// while the current policy admits its original tuple, and stops when it does
// not. A connection that an unconditional ALLOW also admits keeps passing;
// one that a conditional DENY's opened window covers stops.

const (
	conditionalScopeChain  = "conditional_scope"
	conditionalPolicyChain = "conditional_policy"
)

// predicates lowers the conditional predicates of one snapshot.
type predicates struct {
	snap       *rules.Snapshot
	queueID    int
	identities identityIndex
}

func newPredicates(snap *rules.Snapshot, queueID int) (*predicates, error) {
	idx, err := newIdentityIndex(snap.IdentityBindings)
	if err != nil {
		return nil, err
	}
	return &predicates{snap: snap, queueID: queueID, identities: idx}, nil
}

func conditional(e rules.Entry) bool {
	return e.HasIdentityPredicate() || e.HasSchedulePredicate()
}

func terminal(a rules.Action) bool {
	return a == rules.ActionAllow || a == rules.ActionDeny || a == rules.ActionReset
}

// kernelDecided reports whether nftables decides e: a terminal rule that is
// not queued to the engine.
func (p *predicates) kernelDecided(e rules.Entry) bool {
	return terminal(e.Action) && !queuedToEngine(e, p.queueID)
}

// alternatives returns the predicate clauses of e, any one of which must
// hold: [""] for an unconditional rule, none for an identity predicate no
// bound address satisfies. ct selects the established-connection form.
func (p *predicates) alternatives(e rules.Entry, ct bool) ([]string, error) {
	schedule := ""
	if e.HasSchedulePredicate() {
		set, err := scheduleSetOf(e)
		if err != nil {
			return nil, err
		}
		schedule = "meta time @" + set.name
	}
	if !e.HasIdentityPredicate() {
		return []string{schedule}, nil
	}
	var out []string
	for _, id := range p.identities.identityAlternatives(e, ct) {
		out = append(out, strings.TrimSpace(id+" "+schedule))
	}
	return out, nil
}

// guard adds e's predicates to the lines compileEntry emitted for it. A
// queued rule's lines are unchanged; a predicate nothing satisfies leaves
// no line.
func (p *predicates) guard(e rules.Entry, lines []string) ([]string, error) {
	if queuedToEngine(e, p.queueID) || !conditional(e) {
		return lines, nil
	}
	alts, err := p.alternatives(e, false)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(lines)*len(alts))
	for _, line := range lines {
		for _, alt := range alts {
			out = append(out, alt+" "+line)
		}
	}
	return out, nil
}

// scheduleSets returns the time sets the kernel-decided rules reference,
// by name.
func (p *predicates) scheduleSets() []scheduleSet {
	byName := map[string]scheduleSet{}
	for _, e := range p.snap.Firewall {
		if !p.kernelDecided(e) || !e.HasSchedulePredicate() {
			continue
		}
		// An invalid schedule fails CompileFirewall in alternatives.
		if set, err := scheduleSetOf(e); err == nil {
			byName[set.name] = set
		}
	}
	out := make([]scheduleSet, 0, len(byName))
	for _, set := range byName {
		out = append(out, set)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// writeSets declares the identity and schedule sets the kernel-decided rules
// reference, with c's schedule horizon.
func (p *predicates) writeSets(buf *bytes.Buffer, c *Compiler) error {
	var ids []identitySet
	seen := map[identitySet]bool{}
	for _, e := range p.snap.Firewall {
		if !p.kernelDecided(e) {
			continue
		}
		for _, set := range p.identities.identitySets(e) {
			if !seen[set] {
				seen[set] = true
				ids = append(ids, set)
			}
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].name() < ids[j].name() })
	for _, set := range ids {
		p.identities.writeIdentitySet(buf, set)
	}
	from, to := c.horizon()
	for _, set := range p.scheduleSets() {
		if err := set.write(buf, from, to); err != nil {
			return err
		}
	}
	return nil
}

// rechecks reports whether established connections need deciding again:
// some kernel-decided rule is conditional.
func (p *predicates) rechecks() bool {
	return slices.ContainsFunc(p.snap.Firewall, func(e rules.Entry) bool { return p.kernelDecided(e) && conditional(e) })
}

// writeRecheckJump sends established packets to the recheck, when needed.
// It goes before the established accept of the forward chain.
func (p *predicates) writeRecheckJump(buf *bytes.Buffer) {
	if p.rechecks() {
		buf.WriteString("    ct state established jump " + conditionalScopeChain + ";\n")
	}
}

// writeRecheckChains declares the recheck chains, when needed: the scope
// chain sends established packets in the scope of a conditional rule to the
// policy chain, which decides the connection's original tuple as the
// forward chain decides a new connection. return passes the packet on to
// the established accept.
func (p *predicates) writeRecheckChains(buf *bytes.Buffer) error {
	if !p.rechecks() {
		return nil
	}
	entries := kernelOrder(p.snap.Firewall)
	var scope, policy []string
	add := func(dst *[]string, lines []string) {
		for _, l := range lines {
			if !slices.Contains(*dst, l) {
				*dst = append(*dst, l)
			}
		}
	}
	// Port forwards admit their connections ahead of every rule; the
	// engine decides the connections of queued rules.
	policy = append(policy, "ct status dnat return")
	for _, e := range entries {
		if !queuedToEngine(e, p.queueID) || isIEC104Rule(e) {
			continue
		}
		lines, err := p.ctLines(e, []string{""}, "return")
		if err != nil {
			return err
		}
		add(&policy, lines)
	}
	for _, e := range entries {
		if !p.kernelDecided(e) {
			continue
		}
		if conditional(e) {
			lines, err := p.ctLines(e, []string{""}, "goto "+conditionalPolicyChain)
			if err != nil {
				return err
			}
			add(&scope, lines)
		}
		alts, err := p.alternatives(e, true)
		if err != nil {
			return err
		}
		lines, err := p.ctLines(e, alts, recheckVerdict(e.Action))
		if err != nil {
			return err
		}
		add(&policy, lines)
	}
	if p.snap.Default == rules.ActionAllow {
		policy = append(policy, "return")
	} else {
		policy = append(policy, "drop")
	}
	for _, ch := range []struct {
		name  string
		lines []string
	}{{conditionalScopeChain, scope}, {conditionalPolicyChain, policy}} {
		buf.WriteString("  chain " + ch.name + " {\n")
		for _, l := range ch.lines {
			buf.WriteString("    " + l + ";\n")
		}
		buf.WriteString("  }\n")
	}
	return nil
}

// kernelOrder returns firewall entries in the order nftables decides them:
// every ALLOW first, then the other rules, each group by rule ID, so any
// matching ALLOW takes precedence.
func kernelOrder(firewall []rules.Entry) []rules.Entry {
	entries := append([]rules.Entry(nil), firewall...)
	sort.SliceStable(entries, func(i, j int) bool {
		ai, aj := entries[i].Action, entries[j].Action
		if ai != aj {
			return ai == rules.ActionAllow
		}
		return entries[i].ID < entries[j].ID
	})
	return entries
}

// recheckVerdict is the recheck form of a terminal action: an ALLOW returns
// to the established accept. RESET is lowered per protocol by ctLines.
func recheckVerdict(a rules.Action) string {
	switch a {
	case rules.ActionAllow:
		return "return"
	case rules.ActionReset:
		return "reject"
	default:
		return "drop"
	}
}

// ctLines lowers e's scope for an established packet of either direction:
// the original tuple the forward chain saw on the connection's first packet,
// read from conntrack (opener and post-DNAT server address and port), with
// the zones swapped on replies. Each line carries one of alts.
func (p *predicates) ctLines(e rules.Entry, alts []string, verdict string) ([]string, error) {
	zoneIfaces := p.snap.ZoneIfaces
	type direction struct {
		clause  string
		in, out []string
	}
	dirs := []direction{{"", e.SourceZones, e.DestZones}}
	if len(e.SourceZones) > 0 || len(e.DestZones) > 0 {
		dirs = []direction{
			{"ct direction original", e.SourceZones, e.DestZones},
			{"ct direction reply", e.DestZones, e.SourceZones},
		}
	}
	protos := e.Protocols
	if len(protos) == 0 {
		protos = []rules.Protocol{{}}
	}
	var out []string
	for _, d := range dirs {
		for _, proto := range protos {
			match, err := ctProtocolMatch(proto)
			if err != nil {
				return nil, fmt.Errorf("entry %s: %w", e.ID, err)
			}
			parts := []string{d.clause, zoneClause("iifname", d.in, zoneIfaces), zoneClause("oifname", d.out, zoneIfaces), match}
			if len(e.Sources) > 0 {
				parts = append(parts, fmt.Sprintf("ct original ip saddr { %s }", strings.Join(e.Sources, ", ")))
			}
			if len(e.Destinations) > 0 {
				parts = append(parts, fmt.Sprintf("ct reply ip saddr { %s }", strings.Join(e.Destinations, ", ")))
			}
			for _, alt := range alts {
				for _, v := range verdictsFor(verdict, proto) {
					out = append(out, joinClauses(append(append(append([]string(nil), parts...), alt), v...)))
				}
			}
		}
	}
	return out, nil
}

// verdictsFor returns the verdict clauses of one protocol line: a reject is
// a TCP reset for TCP and ICMP administratively prohibited otherwise, so an
// any-protocol line splits into a TCP line and one for the rest.
func verdictsFor(verdict string, proto rules.Protocol) [][]string {
	if verdict != "reject" {
		return [][]string{{verdict}}
	}
	const tcpReset, prohibited = "reject with tcp reset", "reject with icmpx type admin-prohibited"
	switch strings.ToLower(strings.TrimSpace(proto.Name)) {
	case "tcp":
		return [][]string{{tcpReset}}
	case "":
		return [][]string{{"meta l4proto tcp", tcpReset}, {prohibited}}
	default:
		return [][]string{{prohibited}}
	}
}

// ctProtocolMatch is protocolMatch for an established packet: the server
// port is the reply's source port, in both directions.
func ctProtocolMatch(p rules.Protocol) (string, error) {
	name := strings.ToLower(strings.TrimSpace(p.Name))
	if (name == "tcp" || name == "udp") && p.Port != "" {
		lo, hi, err := rules.ParsePortRange(p.Port)
		if err != nil {
			return "", fmt.Errorf("invalid %s port: %w", name, err)
		}
		if lo == hi {
			return fmt.Sprintf("meta l4proto %s ct reply proto-src %d", name, lo), nil
		}
		return fmt.Sprintf("meta l4proto %s ct reply proto-src %d-%d", name, lo, hi), nil
	}
	return protocolMatch(p)
}

func joinClauses(parts []string) string {
	var kept []string
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, " ")
}
