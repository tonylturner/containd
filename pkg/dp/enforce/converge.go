// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"fmt"
	"slices"
	"strings"
)

// Everything in the dynamic table belongs to containd, but the table can
// hold the layout of another containd version: before 0.1.35 it held the
// whole policy (filter and NAT chains, zone sets) and a block_flows set
// without a protocol field. Each apply converges it to the current layout
// and keeps only the elements of the current dynamic sets.

// TableLayout is the live layout of a dynamic table.
type TableLayout struct {
	Exists  bool
	Chains  []LiveChain
	Objects []LiveObject
	// LegacyFlowBlocks are the elements of a block_flows set without the
	// protocol field, each expanded to the tcp and udp elements of the
	// current type it matched, with its remaining timeout.
	LegacyFlowBlocks []string
}

// LiveChain is one chain of a live table. Type, Hook and Policy are empty
// for a regular chain.
type LiveChain struct {
	Name, Type, Hook, Policy string
	Prio                     int
}

// LiveObject is one named object of a live table other than a chain.
type LiveObject struct {
	// Kind is the nft object keyword: set, map, counter, ct helper, ...
	Kind string
	Name string
	// Type and Flags describe sets and maps; Type joins concatenated
	// fields with " . ".
	Type  string
	Flags []string
}

// legacyFlowType is the block_flows key type before the protocol field.
const legacyFlowType = "ipv4_addr . ipv4_addr . inet_service"

// dynamicChainPriority is the priority of every dynamic base chain.
const dynamicChainPriority = -10

// InstallScript returns the transaction that installs compiled, c's
// ruleset, over a dynamic table in state live: it removes every chain and
// object of the table that the current layout does not define identically,
// then runs retire (the tables of a previous name, or "") and compiled,
// then restores the flow blocks of a legacy set. Nothing is removed when
// the table already has the current layout, so its set elements are kept.
func (c *Compiler) InstallScript(live TableLayout, retire, compiled string) string {
	before, after := c.converge(live)
	return before + retire + compiled + after
}

func (c *Compiler) converge(live TableLayout) (before, after string) {
	if !live.Exists {
		return "", ""
	}
	table := c.DynamicTable()
	var stale []string
	for _, ch := range live.Chains {
		if !currentChain(ch) {
			stale = append(stale, fmt.Sprintf("delete chain inet %s %s\n", table, ch.Name))
		}
	}
	for _, obj := range live.Objects {
		if !currentObject(obj) {
			stale = append(stale, fmt.Sprintf("delete %s inet %s %s\n", obj.Kind, table, obj.Name))
		}
	}
	if len(stale) == 0 {
		return "", ""
	}
	// Flushing every chain first drops the rules that reference the stale
	// chains and sets, so they can be deleted in the same transaction.
	var b strings.Builder
	for _, ch := range live.Chains {
		fmt.Fprintf(&b, "flush chain inet %s %s\n", table, ch.Name)
	}
	b.WriteString(strings.Join(stale, ""))
	var restore strings.Builder
	for _, elems := range live.LegacyFlowBlocks {
		fmt.Fprintf(&restore, "add element inet %s block_flows { %s }\n", table, elems)
	}
	return b.String(), restore.String()
}

// currentChain reports whether ch is a chain of the current layout with the
// same hook, type, priority and policy. A base chain's hook and priority
// cannot change in place, so any difference recreates it.
func currentChain(ch LiveChain) bool {
	if ch.Name == "revocations" {
		return ch.Hook == "" && ch.Type == ""
	}
	for _, want := range dynamicChains {
		if ch.Name == want.name {
			return ch.Type == "filter" && ch.Hook == want.hook && ch.Prio == dynamicChainPriority && ch.Policy == "accept"
		}
	}
	return false
}

// currentObject reports whether obj is a set of the current layout with the
// same type and flags, whose elements can be kept.
func currentObject(obj LiveObject) bool {
	if obj.Kind != "set" {
		return false
	}
	for _, set := range dynamicSets() {
		if obj.Name == set[0] {
			return obj.Type == set[1] && slices.Equal(obj.Flags, []string{"timeout"})
		}
	}
	return false
}
