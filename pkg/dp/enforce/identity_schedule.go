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
// ends. nftables evaluates them on every line of the rules it handles
// itself, effects included (RATE_LIMIT meters, TAG counts); rules queued to
// the engine keep their unconditional queue line and the engine decides
// their predicates per message.
//
// The conntrack fast path would otherwise keep an established connection
// that a conditional rule no longer admits, so established packets in the
// L3/L4 scope of a conditional rule are decided again, in both directions,
// before that accept (conditionalScopeChain): the connection keeps passing
// while the current policy admits its original tuple, and stops when it does
// not. A connection that an unconditional ALLOW also admits keeps passing;
// one that a conditional DENY's opened window covers stops. Only deciding
// rules (rules.DecisionOrder) take part: effects never admit or stop a
// connection.
//
// A queued conditional ALLOW (rechecksQueued) takes part too: its queue line
// sees only the client's packets, which the engine decides, so the replies
// and the server's own packets of its connections are rechecked against the
// rule's predicates in the kernel.

const (
	conditionalScopeChain  = "conditional_scope"
	conditionalPolicyChain = "conditional_policy"
)

// predicates lowers the conditional predicates of one snapshot.
type predicates struct {
	snap       *rules.Snapshot
	queueID    int
	identities identityIndex
	zones      zoneIndex
	// gate maps the egress zones of the gate selection to their
	// connection-mark indices (zoneLowering.gate).
	gate map[string]uint8
	// recheck is set, per target, once writeRecheckChains has declared
	// its recheck chains.
	recheck [3]bool
}

func newPredicates(snap *rules.Snapshot, queueID int) (*predicates, error) {
	idx, err := newIdentityIndex(snap.IdentityBindings)
	if err != nil {
		return nil, err
	}
	zones, err := newZoneIndex(snap.ZoneIfaces)
	if err != nil {
		return nil, err
	}
	gate := make(map[string]uint8, len(snap.Gate.Zones))
	for _, z := range snap.Gate.Zones {
		gate[z.Name] = z.Index
	}
	return &predicates{snap: snap, queueID: queueID, identities: idx, zones: zones, gate: gate}, nil
}

// lowering returns the zone lowering of target.
func (p *predicates) lowering(target chainTarget) zoneLowering {
	return zoneLowering{idx: p.zones, target: target, gate: p.gate}
}

// recheckChains names the recheck chains of target: the scope chain and
// the policy chain it sends established packets to.
func (t chainTarget) recheckChains() (scope, policy string) {
	switch t {
	case targetGateInput:
		return GateInputChain + "_scope", GateInputChain + "_policy"
	case targetGateReply:
		return GateReplyChain + "_scope", GateReplyChain + "_policy"
	}
	return conditionalScopeChain, conditionalPolicyChain
}

func conditional(e rules.Entry) bool {
	return e.HasIdentityPredicate() || e.HasSchedulePredicate()
}

// kernelDecided reports whether nftables decides e: a deciding rule that is
// not queued to the engine.
func (p *predicates) kernelDecided(e rules.Entry) bool {
	return e.Action.Decides() && !rules.MonitorICS(e, p.snap.DPIMode) && !queuedToEngine(e, p.queueID)
}

// rechecksQueued reports whether e is a conditional ALLOW queued to the
// engine whose replies the kernel rechecks. IEC104 rules are not: their
// steering queues both directions of a session to the engine.
func (p *predicates) rechecksQueued(e rules.Entry) bool {
	return !rules.MonitorICS(e, p.snap.DPIMode) && queuedToEngine(e, p.queueID) &&
		!isIEC104Rule(e) && e.Action == rules.ActionAllow && conditional(e)
}

// kernelGuarded reports whether the kernel evaluates e's predicates: on
// e's own lines, or on the recheck of its connections' replies.
func (p *predicates) kernelGuarded(e rules.Entry) bool {
	return !queuedToEngine(e, p.queueID) || p.rechecksQueued(e)
}

// alternative is one predicate clause; family is the address family its
// identity set requires (0: IPv4, 1: IPv6), -1 for none.
type alternative struct {
	family int
	clause string
}

// alternatives returns the predicate clauses of e, any one of which must
// hold: one empty clause for an unconditional rule, none for an identity
// predicate no bound address satisfies. ct selects the
// established-connection form.
func (p *predicates) alternatives(e rules.Entry, ct bool) ([]alternative, error) {
	schedule := ""
	if e.HasSchedulePredicate() {
		set, err := scheduleSetOf(e)
		if err != nil {
			return nil, err
		}
		schedule = "meta time @" + set.name
	}
	if !e.HasIdentityPredicate() {
		return []alternative{{family: -1, clause: schedule}}, nil
	}
	var out []alternative
	for _, set := range p.identities.identitySets(e) {
		out = append(out, alternative{family: set.family, clause: strings.TrimSpace(set.match(ct) + " " + schedule)})
	}
	return out, nil
}

// guard adds e's predicates to the lines compileEntry emitted for it, for
// every action. A queued rule's lines are unchanged. A line that matches
// both directions of a connection (ruleLine.ct) matches its opener from
// conntrack; every other line sees only packets it takes for a
// connection's first, sent by the opener. A line restricted to one address
// family takes only that family's identity clauses, and a predicate nothing
// satisfies leaves no line.
func (p *predicates) guard(e rules.Entry, lines []ruleLine) ([]string, error) {
	out := make([]string, 0, len(lines))
	if queuedToEngine(e, p.queueID) || !conditional(e) {
		for _, l := range lines {
			out = append(out, l.text)
		}
		return out, nil
	}
	alts, err := p.alternatives(e, false)
	if err != nil {
		return nil, err
	}
	ctAlts, err := p.alternatives(e, true)
	if err != nil {
		return nil, err
	}
	for _, l := range lines {
		use := alts
		if l.ct {
			use = ctAlts
		}
		for _, alt := range inFamily(use, l.family) {
			out = append(out, joinClauses([]string{alt.clause, l.text}))
		}
	}
	return out, nil
}

// inFamily returns the alternatives a line restricted to family can take.
func inFamily(alts []alternative, family int) []alternative {
	if family == familyAny {
		return alts
	}
	var out []alternative
	for _, a := range alts {
		if a.family < 0 || a.family == family {
			out = append(out, a)
		}
	}
	return out
}

// scheduleSets returns the time sets the rules nftables guards reference,
// by name.
func (p *predicates) scheduleSets() []scheduleSet {
	byName := map[string]scheduleSet{}
	for _, e := range p.snap.Firewall {
		if !p.kernelGuarded(e) || !e.HasSchedulePredicate() {
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

// writeSets declares the identity and schedule sets the rules nftables
// guards reference, with c's schedule horizon.
func (p *predicates) writeSets(buf *bytes.Buffer, c *Compiler) error {
	var ids []identitySet
	seen := map[identitySet]bool{}
	for _, e := range p.snap.Firewall {
		if !p.kernelGuarded(e) {
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

// writeRecheckJump sends established packets to target's recheck, when
// writeRecheckChains declared it. It goes before the established accept of
// target's chain.
func (p *predicates) writeRecheckJump(buf *bytes.Buffer, target chainTarget) {
	if p.recheck[target] {
		scope, _ := target.recheckChains()
		buf.WriteString("    ct state established jump " + scope + ";\n")
	}
}

// writeRecheckChains declares target's recheck chains, when needed: the
// scope chain sends established packets in the scope of a conditional rule
// (kernel-decided, or a queued ALLOW) to the policy chain, which decides
// the connection's original tuple as the forward chain decides a new
// connection. return passes the packet on to the established accept. No
// conditional rule that can match anything, no recheck.
func (p *predicates) writeRecheckChains(buf *bytes.Buffer, target chainTarget) error {
	var entries []rules.Entry
	for _, i := range rules.DecisionOrder(p.snap.Firewall) {
		entries = append(entries, p.snap.Firewall[i])
	}
	var scope, policy []string
	add := func(dst *[]string, lines []string) {
		for _, l := range lines {
			if !slices.Contains(*dst, l) {
				*dst = append(*dst, l)
			}
		}
	}
	unguarded := []alternative{{family: familyAny}}
	scopeChain, policyChain := target.recheckChains()
	// Port forwards admit their connections ahead of every rule; the
	// engine decides the client messages of queued rules, and a queued
	// conditional ALLOW admits the rest of its connections while its
	// predicates hold.
	policy = append(policy, "ct status dnat return")
	for _, e := range entries {
		if !queuedToEngine(e, p.queueID) || isIEC104Rule(e) {
			continue
		}
		alts := unguarded
		if p.rechecksQueued(e) {
			lines, err := p.ctLines(target, e, unguarded, "goto "+policyChain)
			if err != nil {
				return err
			}
			add(&scope, lines)
			if alts, err = p.alternatives(e, true); err != nil {
				return err
			}
		}
		lines, err := p.ctLines(target, e, alts, "return")
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
			lines, err := p.ctLines(target, e, unguarded, "goto "+policyChain)
			if err != nil {
				return err
			}
			add(&scope, lines)
		}
		alts, err := p.alternatives(e, true)
		if err != nil {
			return err
		}
		lines, err := p.ctLines(target, e, alts, recheckVerdict(e.Action))
		if err != nil {
			return err
		}
		add(&policy, lines)
	}
	if len(scope) == 0 {
		return nil
	}
	p.recheck[target] = true
	if p.snap.Default == rules.ActionAllow {
		policy = append(policy, "return")
	} else {
		policy = append(policy, "drop")
	}
	for _, ch := range []struct {
		name  string
		lines []string
	}{{scopeChain, scope}, {policyChain, policy}} {
		buf.WriteString("  chain " + ch.name + " {\n")
		for _, l := range ch.lines {
			buf.WriteString("    " + l + ";\n")
		}
		buf.WriteString("  }\n")
	}
	return nil
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

// ctLines lowers e's scope for an established packet of the directions
// target sees: the original tuple the forward chain saw on the connection's
// first packet, read from conntrack (opener and post-DNAT server address
// and port), with the zones swapped on replies (zoneLowering.ctDirections).
// Each line carries one of alts in its address family. A rule that matches
// nothing has none.
func (p *predicates) ctLines(target chainTarget, e rules.Entry, alts []alternative, verdict string) ([]string, error) {
	dirs, ok := p.lowering(target).ctDirections(e)
	if !ok {
		return nil, nil
	}
	scopes, err := addrScopes(e)
	if err != nil {
		return nil, err
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
			for _, s := range scopes {
				parts := append([]string{d.clause, d.in, d.out, match}, s.conntrack()...)
				for _, alt := range inFamily(alts, s.family) {
					for _, v := range verdictsFor(verdict, proto) {
						out = append(out, joinClauses(append(append(append([]string(nil), parts...), alt.clause), v...)))
					}
				}
			}
		}
	}
	return out, nil
}

// verdictsFor returns the verdict clauses of one protocol line: a reject is
// RESET's (actions.go), a TCP reset for TCP and ICMP administratively
// prohibited otherwise, so an any-protocol line splits into a TCP line and
// one for the rest.
func verdictsFor(verdict string, proto rules.Protocol) [][]string {
	if verdict != "reject" {
		return [][]string{{verdict}}
	}
	switch protocolName(proto) {
	case "tcp":
		return [][]string{{rejectTCP}}
	case "":
		return [][]string{{"meta l4proto tcp", rejectTCP}, {rejectOther}}
	default:
		return [][]string{{rejectOther}}
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
