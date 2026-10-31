// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Identity and schedule predicates remain live in ordered transport policy,
// including inspection terminals. Their unguarded scope union dispatches
// established packets before any admission fast path.

const (
	conditionalScopeChain  = "conditional_scope"
	conditionalPolicyChain = "ordered_s2"
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

// kernelGuarded includes all enforcing terminals and effects. Inspection
// steering alone ignores identity and schedule; its S2 admission does not.
func (p *predicates) kernelGuarded(e rules.Entry) bool {
	return !rules.MonitorICS(e, p.snap.DPIMode)
}

// Inspection terminals admit transport irrespective of their message
// action. Their time sets must therefore expire like ALLOW, not widen
// transport admission beyond the planner's horizon like a plain DENY.
func (p *predicates) scheduleSet(e rules.Entry) (scheduleSet, error) {
	if e.Action.Decides() && queuedToEngine(e, p.queueID) {
		e.Action = rules.ActionAllow
	}
	return scheduleSetOf(e)
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
		set, err := p.scheduleSet(e)
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

// guard adds e's predicates to the lines the header or meter compiler emitted for it, for
// effects. Steering alone ignores current predicates. A line that matches
// both directions of a connection (ruleLine.ct) matches its opener from
// conntrack; every other line sees only packets it takes for a
// connection's first, sent by the opener. A line restricted to one address
// family takes only that family's identity clauses, and a predicate nothing
// satisfies leaves no line.
func (p *predicates) guard(e rules.Entry, lines []ruleLine) ([]string, error) {
	return p.guardFor(targetForward, e, lines)
}

func (p *predicates) guardFor(target chainTarget, e rules.Entry, lines []ruleLine) ([]string, error) {
	var out []string
	for _, l := range lines {
		alts, err := p.alternatives(e, l.ct)
		if err != nil {
			return nil, err
		}
		vias := []directionalClause{{}}
		if len(e.ViaForwards) != 0 {
			if !l.ct || l.family == 1 {
				continue
			}
			vias = forwardAlternatives(p.snap, e, target)
		}
		for _, alt := range inFamily(alts, l.family) {
			if len(e.ViaForwards) != 0 && alt.family == 1 {
				continue // owned publications are IPv4 only
			}
			for _, via := range vias {
				if direction, ok := l.direction.intersect(via.direction); ok {
					out = append(out, joinClauses([]string{alt.clause, direction.clause(), via.text, l.text}))
				}
			}
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
		if set, err := p.scheduleSet(e); err == nil {
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

// writeRecheckChains emits only the unguarded conditional scope union;
// every hit enters the very same ordered body as new/stale packets.
func (p *predicates) writeRecheckChains(buf *bytes.Buffer, target chainTarget) error {
	scope, policy := target.recheckChains()
	var lines []string
	for _, e := range p.snap.Firewall {
		if !e.Action.Decides() || rules.MonitorICS(e, p.snap.DPIMode) || !conditional(e) {
			continue
		}
		ls, err := p.ctLines(target, e, []alternative{{family: familyAny}}, "goto "+policy, false)
		if err != nil {
			return err
		}
		lines = append(lines, ls...)
	}
	if len(lines) == 0 {
		return nil
	}
	p.recheck[target] = true
	fmt.Fprintln(buf, "  chain "+scope+" {")
	for _, l := range lines {
		fmt.Fprintln(buf, "    "+l+";")
	}
	fmt.Fprintln(buf, "  }")
	return nil
}

func (p *predicates) writeRecheckJump(buf *bytes.Buffer, target chainTarget) {
	if p.recheck[target] {
		scope, _ := target.recheckChains()
		fmt.Fprintln(buf, "    ct state established jump "+scope+";")
	}
}

// ctLines lowers e's scope for a tracked packet of the directions
// target sees: the original tuple the forward chain saw on the connection's
// first packet, read from conntrack (opener and post-DNAT server address
// and port), with the zones swapped on replies (zoneLowering.ctDirections).
// Each line carries one of alts in its address family. A rule that matches
// nothing has none. Intersect originalOnly with zone and via directions
// before rendering the single direction clause.
func (p *predicates) ctLines(target chainTarget, e rules.Entry, alts []alternative, verdict string, originalOnly bool) ([]string, error) {
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
		direction := d.direction
		if originalOnly {
			var ok bool
			direction, ok = direction.intersect(directionOriginal)
			if !ok {
				continue
			}
		}
		for _, proto := range protos {
			match, err := ctProtocolMatch(proto)
			if err != nil {
				return nil, fmt.Errorf("entry %s: %w", e.ID, err)
			}
			for _, s := range scopes {
				if len(e.ViaForwards) != 0 && s.family == 1 {
					continue
				}
				parts := append([]string{d.in, d.out, match}, s.conntrack()...)
				for _, alt := range inFamily(alts, s.family) {
					if len(e.ViaForwards) != 0 && alt.family == 1 {
						continue
					}
					for _, via := range forwardAlternatives(p.snap, e, target) {
						if merged, ok := direction.intersect(via.direction); ok {
							out = append(out, joinClauses(append(append([]string{merged.clause()}, parts...), alt.clause, via.text, verdict)))
						}
					}
				}
			}
		}
	}
	return out, nil
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
