// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"fmt"
)

// containd owns two nftables tables by name and never touches any other
// table in the namespace:
//
//   - the policy table, inet <TableName>, which every apply replaces as a
//     whole in one transaction;
//   - the blocks table, inet <TableName>_blocks, which holds the temporary
//     block sets and their drop chain. Applies create it if it is missing and
//     keep its elements, so temporary blocks and their timeouts survive
//     policy changes.

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

// writeBlocksTable ensures the blocks table without touching its set
// elements. Its forward chain runs before the policy table's (priority 0),
// and a drop there is final, so a block takes precedence over IEC104
// steering, NFQUEUE and the established-flow accept of the policy table:
// retroactive blocks also stop established flows.
func (c *Compiler) writeBlocksTable(buf *bytes.Buffer) {
	table := BlocksTable(c.policyTable())
	writeBlockSets(buf, table)
	buf.WriteString(fmt.Sprintf("add chain inet %s forward { type filter hook forward priority -10; policy accept; }\n", table))
	buf.WriteString(fmt.Sprintf("flush chain inet %s forward\n", table))
	for _, rule := range []string{
		"ip saddr @block_hosts drop",
		"ip daddr @block_hosts drop",
		"meta l4proto { tcp, udp } ip saddr . ip daddr . meta l4proto . th dport @block_flows drop",
	} {
		buf.WriteString(fmt.Sprintf("add rule inet %s forward %s\n", table, rule))
	}
}

// writeBlockSets declares the blocks table and its sets. Re-adding an
// existing set keeps its elements.
func writeBlockSets(buf *bytes.Buffer, table string) {
	buf.WriteString(fmt.Sprintf("add table inet %s\n", table))
	buf.WriteString(fmt.Sprintf("add set inet %s block_hosts { type ipv4_addr; flags timeout; }\n", table))
	buf.WriteString(fmt.Sprintf("add set inet %s block_flows { type ipv4_addr . ipv4_addr . inet_proto . inet_service; flags timeout; }\n", table))
}
