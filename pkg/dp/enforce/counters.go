// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Every firewall rule has a named counter in the policy table. Counted
// policy matches update it, but established traffic taking the ordered
// admission fast path bypasses ALLOW counters. RATE_LIMIT rules have a
// second counter for packets dropped over the limit. The policy table is
// replaced on every apply, so counters start at zero with each applied
// ruleset; logging need not be on.

// ruleCounterName names the counter of the rule with ID id. Rule IDs are
// free text, so the name is derived from a digest of the ID.
func ruleCounterName(id string) string {
	sum := sha256.Sum256([]byte(id))
	return "rule_" + hex.EncodeToString(sum[:8])
}

// excessCounterName names the counter of the packets a RATE_LIMIT rule
// drops over its limit.
func excessCounterName(id string) string {
	return ruleCounterName(id) + "_excess"
}

// counterStmt is the statement that counts a packet into the rule's
// counter.
func counterStmt(id string) string {
	return fmt.Sprintf("counter name %q", ruleCounterName(id))
}

// writeRuleObjects declares the counters and meter sets of snap's rules
// inside the policy table, before the chains that use them.
func writeRuleObjects(buf *bytes.Buffer, snap *rules.Snapshot) error {
	owner := map[string]string{}
	for _, e := range snap.Firewall {
		name := ruleCounterName(e.ID)
		if other, ok := owner[name]; ok {
			return fmt.Errorf("firewall rules %q and %q need the same counter %s; rule IDs must be unique", other, e.ID, name)
		}
		owner[name] = e.ID
		fmt.Fprintf(buf, "  counter %s { }\n", name)
		if e.Action != rules.ActionRateLimit {
			continue
		}
		fmt.Fprintf(buf, "  counter %s { }\n", excessCounterName(e.ID))
		if err := writeMeterSets(buf, e); err != nil {
			return err
		}
	}
	return nil
}

// CounterValue is the value of one nft counter.
type CounterValue struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// CounterReader reads the named counters of an inet table.
type CounterReader interface {
	ReadCounters(ctx context.Context, table string) (map[string]CounterValue, error)
}

// ReadCounters reads the named counters of inet table.
func (a *NftApplier) ReadCounters(ctx context.Context, table string) (map[string]CounterValue, error) {
	if err := ValidateTableName(table); err != nil {
		return nil, err
	}
	doc, err := a.list(ctx, "list", "counters", "table", "inet", table)
	if err != nil {
		return nil, err
	}
	return parseCounters(doc)
}

func parseCounters(doc []byte) (map[string]CounterValue, error) {
	items, err := nftItems(doc)
	if err != nil {
		return nil, err
	}
	out := map[string]CounterValue{}
	for _, item := range items {
		raw, ok := item["counter"]
		if !ok {
			continue
		}
		var c struct {
			Name    string
			Packets uint64
			Bytes   uint64
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("decode nft counter: %w", err)
		}
		out[c.Name] = CounterValue{Packets: c.Packets, Bytes: c.Bytes}
	}
	return out, nil
}

// RuleCount is the kernel accounting of one firewall rule's counted policy
// matches. Established traffic on the ordered admission fast path bypasses ALLOW
// counters; queued ICS counters measure selected steering, not admission.
// For RATE_LIMIT it also reports packets dropped over the limit.
// A TAG rule counts the connection openers it matched.
type RuleCount struct {
	RuleID      string       `json:"ruleId"`
	Action      rules.Action `json:"action"`
	Packets     uint64       `json:"packets"`
	Bytes       uint64       `json:"bytes"`
	ExcessDrops *uint64      `json:"excessDrops,omitempty"`
}

// RuleCounts maps the counters of the policy table compiled from snap to
// its rules, in snap's order. A missing counter means the table was not
// compiled from snap.
func RuleCounts(snap *rules.Snapshot, counters map[string]CounterValue) ([]RuleCount, error) {
	out := make([]RuleCount, 0, len(snap.Firewall))
	for _, e := range snap.Firewall {
		v, ok := counters[ruleCounterName(e.ID)]
		if !ok {
			return nil, fmt.Errorf("counter of rule %q is missing from the policy table", e.ID)
		}
		rc := RuleCount{RuleID: e.ID, Action: e.Action, Packets: v.Packets, Bytes: v.Bytes}
		if e.Action == rules.ActionRateLimit {
			x, ok := counters[excessCounterName(e.ID)]
			if !ok {
				return nil, fmt.Errorf("excess counter of rule %q is missing from the policy table", e.ID)
			}
			rc.ExcessDrops = &x.Packets
		}
		out = append(out, rc)
	}
	return out, nil
}

// PolicyTable names the table c's rulesets replace, which holds the rule
// counters.
func (c *Compiler) PolicyTable() string {
	return c.policyTable()
}
