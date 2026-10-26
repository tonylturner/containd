// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Identity bindings compile to address sets in the policy table, one per
// label and address family that a rule decided by nftables references:
// identity4_<hex label> (ipv4_addr) and identity6_<hex label> (ipv6_addr).
// A rule with identities matches when the opener's address is in the set of
// any of its labels. Every apply replaces the policy table, sets included,
// so a binding change takes effect with the commit that stages it.

// identityFamilies are the address families of identity sets: their set
// name prefix, set type and source address expressions for the opener of a
// new connection and of an established one.
var identityFamilies = [2]struct{ prefix, setType, saddr, ctSaddr string }{
	{"identity4_", "ipv4_addr", "ip saddr", "ct original ip saddr"},
	{"identity6_", "ipv6_addr", "ip6 saddr", "ct original ip6 saddr"},
}

// identitySetName names the set of label's addresses in a family. Hex keeps
// any label a valid, distinct nft identifier.
func identitySetName(family int, label string) string {
	return identityFamilies[family].prefix + hex.EncodeToString([]byte(label))
}

// identityIndex maps each bound label to its addresses per family, sorted.
type identityIndex map[string][2][]string

func newIdentityIndex(bindings []rules.IdentityBinding) (identityIndex, error) {
	idx := identityIndex{}
	for _, b := range bindings {
		addr, ok := rules.BindingAddr(b.IP)
		if !ok {
			return nil, fmt.Errorf("identity binding has invalid address %q", b.IP)
		}
		family := 0
		if addr.Is6() {
			family = 1
		}
		for _, label := range b.Identities {
			fams := idx[label]
			fams[family] = append(fams[family], addr.String())
			idx[label] = fams
		}
	}
	for label, fams := range idx {
		for f := range fams {
			slices.Sort(fams[f])
		}
		idx[label] = fams
	}
	return idx, nil
}

// identitySet is the set of one label's addresses in one family (0: IPv4,
// 1: IPv6).
type identitySet struct {
	family int
	label  string
}

func (s identitySet) name() string { return identitySetName(s.family, s.label) }

// identitySets returns the sets e's identity predicate matches against, one
// per label and family with bound addresses. A rule whose addresses are
// IPv4 CIDRs takes no IPv6 set: nft cannot match both families in one rule,
// and the rule cannot match an IPv6 flow anyway.
func (idx identityIndex) identitySets(e rules.Entry) []identitySet {
	labels := slices.Clone(e.Identities)
	slices.Sort(labels)
	labels = slices.Compact(labels)
	ipv4Only := len(e.Sources) > 0 || len(e.Destinations) > 0
	var out []identitySet
	for _, label := range labels {
		for f := range identityFamilies {
			if len(idx[label][f]) > 0 && (f == 0 || !ipv4Only) {
				out = append(out, identitySet{f, label})
			}
		}
	}
	return out
}

// identityAlternatives returns the opener clauses of e's identity
// predicate, one per set; ct selects the established-connection form.
func (idx identityIndex) identityAlternatives(e rules.Entry, ct bool) []string {
	var out []string
	for _, set := range idx.identitySets(e) {
		saddr := identityFamilies[set.family].saddr
		if ct {
			saddr = identityFamilies[set.family].ctSaddr
		}
		out = append(out, saddr+" @"+set.name())
	}
	return out
}

// writeIdentitySet declares one identity set.
func (idx identityIndex) writeIdentitySet(buf *bytes.Buffer, set identitySet) {
	fmt.Fprintf(buf, "  set %s {\n    type %s;\n", set.name(), identityFamilies[set.family].setType)
	fmt.Fprintf(buf, "    elements = { %s }\n  }\n", strings.Join(idx[set.label][set.family], ", "))
}

// identityWarnings reports the rules whose identity predicate no bound
// address can satisfy: such a rule matches nothing, ALLOW or DENY.
func identityWarnings(snap *rules.Snapshot, idx identityIndex) []RuleWarning {
	var out []RuleWarning
	for _, e := range snap.Firewall {
		if !e.HasIdentityPredicate() || len(idx.identityAlternatives(e, false)) > 0 {
			continue
		}
		out = append(out, RuleWarning{RuleID: e.ID, Predicate: PredicateIdentity, Action: e.Action,
			Message: fmt.Sprintf("no bound address can match identities %s; the rule matches nothing until one is bound",
				strings.Join(e.Identities, ", "))})
	}
	return out
}
