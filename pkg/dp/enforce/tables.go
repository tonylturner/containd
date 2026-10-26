// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// containd owns two nftables tables by name and never touches any other
// table in the namespace:
//
//   - the policy table, inet <TableName>, which every apply replaces as a
//     whole in one transaction;
//   - the blocks table, inet <TableName>_blocks, which holds the dynamic
//     state: the temporary block sets, the connection revocation sets and
//     the chains that enforce them. Applies create it if it is missing,
//     rewrite its chains and keep its set elements, so blocks, revocations
//     and their timeouts survive policy changes.

const defaultTableName = "containd"

// BlocksTable names the blocks table paired with a policy table.
func BlocksTable(policyTable string) string {
	if policyTable == "" {
		policyTable = defaultTableName
	}
	return policyTable + "_blocks"
}

// DeleteTable returns an nft script that deletes inet table name whether or
// not it exists. Followed by the table's definition in the same script, it
// replaces the table atomically.
func DeleteTable(name string) string {
	return fmt.Sprintf("add table inet %s\ndelete table inet %s\n", name, name)
}

// policyTable is the name of the table c's rulesets replace.
func (c *Compiler) policyTable() string {
	if c.TableName == "" {
		return defaultTableName
	}
	return c.TableName
}

// DeleteTables returns the script that removes both tables c owns, present
// or not.
func (c *Compiler) DeleteTables() string {
	return DeleteTable(c.policyTable()) + DeleteTable(BlocksTable(c.policyTable()))
}

// RetireTables returns the script that removes the tables c installed when
// next owns differently named ones, or "" when next owns the same tables.
// It must precede next's ruleset in one transaction: the new names can
// coincide with an old table of the other role.
func (c *Compiler) RetireTables(next *Compiler) string {
	if c.policyTable() == next.policyTable() {
		return ""
	}
	return c.DeleteTables()
}

// ClearBlocks returns the script that removes every temporary block and
// connection revocation, creating the empty sets if they do not exist yet.
func (c *Compiler) ClearBlocks() string {
	var buf bytes.Buffer
	table := BlocksTable(c.policyTable())
	writeDynamicSets(&buf, table)
	for _, set := range dynamicSets() {
		buf.WriteString(fmt.Sprintf("flush set inet %s %s\n", table, set[0]))
	}
	return buf.String()
}

// blocksChains are the base chains of the blocks table. Each runs before
// the policy table's chain on its hook (priority 0), and a drop or reject
// there is final, so revocations and blocks take precedence over IEC104
// steering, NFQUEUE and the established-flow accepts of the policy table:
// they also stop established connections. Kernel-generated resets pass
// output through the revocations chain unharmed.
var blocksChains = []struct{ name, hook string }{
	{"input", "input"},
	{"forward", "forward"},
	{"output", "output"},
}

// writeBlocksTable ensures the blocks table and rewrites its chains without
// touching its set elements. locals is the resolved local input of the
// snapshot: management traffic is exempt from revocations.
func (c *Compiler) writeBlocksTable(buf *bytes.Buffer, locals []rules.LocalServiceRule) error {
	exemptIn, exemptOut, err := c.managementExemptions(locals)
	if err != nil {
		return err
	}
	exempt := map[string][]string{"input": exemptIn, "output": exemptOut}
	table := BlocksTable(c.policyTable())
	writeDynamicSets(buf, table)
	buf.WriteString(fmt.Sprintf("add chain inet %s revocations\n", table))
	for _, ch := range blocksChains {
		buf.WriteString(fmt.Sprintf("add chain inet %s %s { type filter hook %s priority -10; policy accept; }\n", table, ch.name, ch.hook))
	}
	buf.WriteString(fmt.Sprintf("flush chain inet %s revocations\n", table))
	for _, ch := range blocksChains {
		buf.WriteString(fmt.Sprintf("flush chain inet %s %s\n", table, ch.name))
	}
	for _, rule := range revocationRules() {
		buf.WriteString(fmt.Sprintf("add rule inet %s revocations %s\n", table, rule))
	}
	for _, ch := range blocksChains {
		for _, rule := range exempt[ch.name] {
			buf.WriteString(fmt.Sprintf("add rule inet %s %s %s\n", table, ch.name, rule))
		}
		buf.WriteString(fmt.Sprintf("add rule inet %s %s jump revocations\n", table, ch.name))
	}
	for _, rule := range []string{
		"ip saddr @block_hosts drop",
		"ip daddr @block_hosts drop",
		"meta l4proto { tcp, udp } ip saddr . ip daddr . meta l4proto . th dport @block_flows drop",
	} {
		buf.WriteString(fmt.Sprintf("add rule inet %s forward %s\n", table, rule))
	}
	return nil
}

// dynamicSets returns the name and type of each set of the blocks table.
func dynamicSets() [][2]string {
	return append([][2]string{
		{"block_hosts", "ipv4_addr"},
		{"block_flows", "ipv4_addr . ipv4_addr . inet_proto . inet_service"},
	}, revocationSets()...)
}

// writeDynamicSets declares the blocks table and its sets. Re-adding an
// existing set keeps its elements.
func writeDynamicSets(buf *bytes.Buffer, table string) {
	buf.WriteString(fmt.Sprintf("add table inet %s\n", table))
	for _, set := range dynamicSets() {
		buf.WriteString(fmt.Sprintf("add set inet %s %s { type %s; flags timeout; }\n", table, set[0], set[1]))
	}
}
