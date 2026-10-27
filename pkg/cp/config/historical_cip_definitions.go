// SPDX-License-Identifier: Apache-2.0
package config

// historicalCIPBuiltinDefinitions freezes every shipped enip definition for
// exact-match upgrades only. These definitions are identical on main and
// release branches since ee2ec364; operator-edited copies are not rewritten.
func historicalCIPBuiltinDefinitions() []IDSRule {
	return []IDSRule{
		{
			ID:          "IDS-CIP-001",
			Title:       "CIP Reset Service",
			Description: "CIP Reset (service 0x05) restores factory defaults — potential sabotage.",
			Proto:       "enip",
			Severity:    "critical",
			Message:     "CIP reset service invoked",
			When:        IDSCondition{Field: "attr.service_code", Op: "equals", Value: float64(0x05)},
			Labels:      map[string]string{"mitre": "T0816", "category": "ics"},
		},
		{
			ID:          "IDS-CIP-002",
			Title:       "CIP PLC Mode Change",
			Description: "CIP service 0x07 changes PLC run/stop state.",
			Proto:       "enip",
			Severity:    "critical",
			Message:     "CIP PLC run/stop state change",
			When:        IDSCondition{Field: "attr.service_code", Op: "equals", Value: float64(0x07)},
			Labels:      map[string]string{"mitre": "T0881", "category": "ics"},
		},
	}
}

// upgradeIndustrialBuiltins018 is the shared schema step. Only complete,
// shipped definitions (ignoring enabled alone) can be removed or updated.
func upgradeIndustrialBuiltins018(cfg *Config) (removed, updated []string) {
	if !beforeIndustrialScope(cfg.SchemaVersion) {
		return nil, nil
	}
	removed = removeRetiredBuiltins(cfg)
	for i, rule := range cfg.IDS.Rules {
		for _, stock := range historicalCIPBuiltinDefinitions() {
			if rule.ID == stock.ID && sameBuiltin(rule, stock) {
				cfg.IDS.Rules[i].Proto = "cip"
				updated = append(updated, rule.ID)
				break
			}
		}
	}
	return removed, updated
}
