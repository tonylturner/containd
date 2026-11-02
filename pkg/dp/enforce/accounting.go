// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"maps"
	"sort"
	"strings"
)

// AccountingTable names the persistent routed-traffic accounting table.
func AccountingTable(table string) string {
	if table == "" {
		table = defaultTableName
	}
	return table + "_acct"
}

// AccountingPair binds a named counter to one directional cross-zone pair.
type AccountingPair struct{ From, To, Counter string }

// Accounting is an immutable table build. A rebuild always starts a new epoch.
type Accounting struct {
	Table, Epoch string
	devices      map[string]string
	Pairs        []AccountingPair
}

func NewAccounting(table string, devices map[string]string) *Accounting {
	a := &Accounting{Table: AccountingTable(table), Epoch: rand.Text(), devices: maps.Clone(devices)}
	seen := map[string]bool{}
	var zones []string
	for _, z := range devices {
		if !seen[z] {
			zones = append(zones, z)
			seen[z] = true
		}
	}
	sort.Strings(zones)
	for i, from := range zones {
		for j, to := range zones {
			if from == to {
				continue
			}
			a.Pairs = append(a.Pairs, AccountingPair{from, to, fmt.Sprintf("pair_%d_%d", i+1, j+1)})
		}
	}
	return a
}

// Matches reports whether an existing build covers exactly this membership.
func (a *Accounting) Matches(table string, devices map[string]string) bool {
	return a != nil && a.Table == AccountingTable(table) && maps.Equal(a.devices, devices)
}

// Script replaces only the accounting table. It has no packet verdicts.
// Forward priority 100 runs after policy, including queue continuation, and
// before postrouting SNAT. Device membership is independent of address/NAT state.
func (a *Accounting) Script() (string, error) {
	if err := ValidateTableName(strings.TrimSuffix(a.Table, "_acct")); err != nil {
		return "", err
	}
	var b bytes.Buffer
	b.WriteString(DeleteTable(a.Table))
	fmt.Fprintf(&b, "table inet %s {\n", a.Table)

	pairCounters := map[[2]string]string{}
	for _, p := range a.Pairs {
		pairCounters[[2]string{p.From, p.To}] = p.Counter
		fmt.Fprintf(&b, " counter %s { }\n", p.Counter)
	}
	// Resolve the device-to-zone map into an object map: every device pair
	// references its zone pair's shared counter, with one lookup per packet.
	devices := make([]string, 0, len(a.devices))
	for d := range a.devices {
		if err := ValidateInterfaceName(d); err != nil {
			return "", err
		}
		devices = append(devices, d)
	}
	sort.Strings(devices)
	fmt.Fprintln(&b, " map device_pairs { type ifname . ifname : counter;")
	if len(a.Pairs) > 0 {
		fmt.Fprint(&b, " elements = { ")
		first := true
		for _, from := range devices {
			for _, to := range devices {
				if a.devices[from] == a.devices[to] {
					continue
				}
				if !first {
					fmt.Fprint(&b, ", ")
				}
				first = false
				fmt.Fprintf(&b, "%q . %q : %q", from, to, pairCounters[[2]string{a.devices[from], a.devices[to]}])
			}
		}
		fmt.Fprintln(&b, " }")
	}
	fmt.Fprintln(&b, " }")
	fmt.Fprintln(&b, " chain forward { type filter hook forward priority 100; policy accept;")
	fmt.Fprintln(&b, " counter name meta iifname . meta oifname map @device_pairs")
	fmt.Fprintln(&b, " }\n}")
	return b.String(), nil
}

// AccountingReader reads a table build's named counters without lifecycle locks.
type AccountingReader interface {
	ReadAccountingCounters(context.Context, string) (map[string]CounterValue, error)
}

// ReadAccountingCounters accepts the derived table name; only its base name is
// subject to the configured-name length limit (the suffix has reserved space).
func (a *NftApplier) ReadAccountingCounters(ctx context.Context, table string) (map[string]CounterValue, error) {
	if !strings.HasSuffix(table, "_acct") {
		return nil, fmt.Errorf("not an accounting table: %q", table)
	}
	if err := ValidateTableName(strings.TrimSuffix(table, "_acct")); err != nil {
		return nil, err
	}
	doc, err := a.list(ctx, "list", "counters", "table", "inet", table)
	if err != nil {
		return nil, err
	}
	return parseCounters(doc)
}
