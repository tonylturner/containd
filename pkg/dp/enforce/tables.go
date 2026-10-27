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
//   - the dynamic table, inet <TableName> (default inet containd), which
//     holds the temporary block sets, the connection revocation sets and the
//     chains that enforce them. Applies create it if it is missing, rewrite
//     its chains and keep its set elements, so blocks, revocations and their
//     timeouts survive policy changes. Tools address its sets by this name.
//   - the policy table, inet <TableName>_policy, which every apply replaces
//     as a whole in one transaction.

const defaultTableName = "containd"

// DHCPRedirectTable is the inet table the DHCP server owns. Neither table
// above may take its name.
const DHCPRedirectTable = "containd_dhcp"

// maxTableName leaves room for the policy table suffix within the kernel's
// 255-byte object names.
const maxTableName = 255 - len("_policy")

// ValidateTableName checks a dynamic table name. It is the one rule for
// containd's table names: nft's identifier syntax restricted to the
// characters configuration allows, a letter or underscore followed by
// letters, digits, underscores and hyphens. nft cannot address a name that
// starts with a digit or hyphen, or a name that is an nft keyword, even
// quoted. The DHCP redirect table's name is taken. The policy table's name
// needs no check of its own: it ends in "_policy", which no keyword and not
// the DHCP redirect table does.
func ValidateTableName(name string) error {
	if name == "" || len(name) > maxTableName {
		return fmt.Errorf("invalid nft table name %q: want 1-%d characters", name, maxTableName)
	}
	for i, r := range name {
		letter := r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !letter && (i == 0 || (r != '-' && (r < '0' || r > '9'))) {
			return fmt.Errorf("invalid nft table name %q: start with a letter or underscore, then use letters, digits, underscores and hyphens", name)
		}
	}
	if _, ok := nftKeywords[name]; ok {
		return fmt.Errorf("invalid nft table name %q: it is an nft keyword", name)
	}
	if name == DHCPRedirectTable {
		return fmt.Errorf("invalid nft table name %q: it is the DHCP redirect table", name)
	}
	return nil
}

// PolicyTable names the policy table paired with a dynamic table.
func PolicyTable(table string) string {
	if table == "" {
		table = defaultTableName
	}
	return table + "_policy"
}

// DeleteTable returns an nft script that deletes inet table name whether or
// not it exists. Followed by the table's definition in the same script, it
// replaces the table atomically.
func DeleteTable(name string) string {
	return fmt.Sprintf("add table inet %s\ndelete table inet %s\n", name, name)
}

// DynamicTable is the name of c's dynamic table.
func (c *Compiler) DynamicTable() string {
	if c.TableName == "" {
		return defaultTableName
	}
	return c.TableName
}

// policyTable is the name of the table c's rulesets replace.
func (c *Compiler) policyTable() string {
	return PolicyTable(c.DynamicTable())
}

// DeleteTables returns the script that removes both tables c owns, present
// or not.
func (c *Compiler) DeleteTables() string {
	return DeleteTable(c.policyTable()) + DeleteTable(c.DynamicTable())
}

// RetireTables returns the script that removes the tables c installed when
// next owns differently named ones, or "" when next owns the same tables.
// It must precede next's ruleset in one transaction: the new names can
// coincide with an old table of the other role.
func (c *Compiler) RetireTables(next *Compiler) string {
	if c.DynamicTable() == next.DynamicTable() {
		return ""
	}
	return c.DeleteTables()
}

// ClearBlocks returns the script that removes every temporary block and
// connection revocation, creating the empty sets if they do not exist yet.
func (c *Compiler) ClearBlocks() string {
	var buf bytes.Buffer
	table := c.DynamicTable()
	writeDynamicSets(&buf, table)
	for _, set := range dynamicSets() {
		buf.WriteString(fmt.Sprintf("flush set inet %s %s\n", table, set[0]))
	}
	return buf.String()
}

// dynamicChains are the base chains of the dynamic table. Each runs before
// the policy table's chain on its hook (priority 0), and a drop or reject
// there is final, so revocations and blocks take precedence over IEC104
// steering, NFQUEUE and the established-flow accepts of the policy table:
// they also stop established connections. Kernel-generated resets pass
// output through the revocations chain unharmed.
var dynamicChains = []struct{ name, hook string }{
	{"input", "input"},
	{"forward", "forward"},
	{"output", "output"},
}

// writeDynamicTable ensures the dynamic table and rewrites its chains without
// touching its set elements. locals is the resolved local input of the
// snapshot: management traffic is exempt from revocations.
func (c *Compiler) writeDynamicTable(buf *bytes.Buffer, locals []rules.LocalServiceRule) error {
	exemptIn, exemptOut, err := c.managementExemptions(locals)
	if err != nil {
		return err
	}
	exempt := map[string][]string{"input": exemptIn, "output": exemptOut}
	table := c.DynamicTable()
	writeDynamicSets(buf, table)
	buf.WriteString(fmt.Sprintf("add chain inet %s revocations\n", table))
	for _, ch := range dynamicChains {
		buf.WriteString(fmt.Sprintf("add chain inet %s %s { type filter hook %s priority %d; policy accept; }\n", table, ch.name, ch.hook, dynamicChainPriority))
	}
	buf.WriteString(fmt.Sprintf("flush chain inet %s revocations\n", table))
	for _, ch := range dynamicChains {
		buf.WriteString(fmt.Sprintf("flush chain inet %s %s\n", table, ch.name))
	}
	for _, rule := range revocationRules() {
		buf.WriteString(fmt.Sprintf("add rule inet %s revocations %s\n", table, rule))
	}
	for _, ch := range dynamicChains {
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

// dynamicSets returns the name and type of each set of the dynamic table.
func dynamicSets() [][2]string {
	return append([][2]string{
		{"block_hosts", "ipv4_addr"},
		{"block_flows", "ipv4_addr . ipv4_addr . inet_proto . inet_service"},
	}, revocationSets()...)
}

// writeDynamicSets declares the dynamic table and its sets. Re-adding an
// existing set keeps its elements.
func writeDynamicSets(buf *bytes.Buffer, table string) {
	buf.WriteString(fmt.Sprintf("add table inet %s\n", table))
	for _, set := range dynamicSets() {
		buf.WriteString(fmt.Sprintf("add set inet %s %s { type %s; flags timeout; }\n", table, set[0], set[1]))
	}
}
