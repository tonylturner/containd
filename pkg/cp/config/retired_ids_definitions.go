// SPDX-License-Identifier: Apache-2.0
package config

// retiredBuiltinDefinitions freezes the shipped definitions for exact-match upgrade
// only. Definitions are identical on main and release branches since ee2ec364.
func retiredBuiltinDefinitions() []IDSRule {
	return []IDSRule{
		// ── S7comm ────────────────────────────────────────────────
		{
			ID:          "IDS-S7-001",
			Title:       "S7comm PLC Stop",
			Description: "S7comm Stop CPU (FC 0x29) halts PLC program execution.",
			Proto:       "s7comm",
			Severity:    "critical",
			Message:     "S7comm PLC stop command detected",
			When: IDSCondition{
				Field: "attr.function_code", Op: "equals", Value: float64(0x29),
			},
			Labels: map[string]string{"mitre": "T0881", "category": "ics"},
		},
		{
			ID:          "IDS-S7-002",
			Title:       "S7comm Block Download",
			Description: "S7comm block transfer (FC 0x1A-0x1C) may indicate firmware or logic modification.",
			Proto:       "s7comm",
			Severity:    "critical",
			Message:     "S7comm block download detected",
			When: IDSCondition{
				Field: "attr.function_code", Op: "in", Value: []any{float64(0x1A), float64(0x1B), float64(0x1C)},
			},
			Labels: map[string]string{"mitre": "T0839", "category": "ics"},
		},

		// ── BACnet ────────────────────────────────────────────────
		{
			ID:          "IDS-BACNET-001",
			Title:       "BACnet Write Property",
			Description: "BACnet WriteProperty can change setpoints, schedules, or alarm limits.",
			Proto:       "bacnet",
			Severity:    "medium",
			Message:     "BACnet write property detected",
			When: IDSCondition{
				Field: "attr.service", Op: "equals", Value: "WriteProperty",
			},
			Labels: map[string]string{"mitre": "T0855", "category": "ics"},
		},
		{
			ID:          "IDS-BACNET-002",
			Title:       "BACnet Device Communication Control",
			Description: "DeviceCommunicationControl can silence a device on the network.",
			Proto:       "bacnet",
			Severity:    "high",
			Message:     "BACnet device communication control detected",
			When: IDSCondition{
				Field: "attr.service", Op: "equals", Value: "DeviceCommunicationControl",
			},
			Labels: map[string]string{"mitre": "T0814", "category": "ics"},
		},

		// ── OPC UA ────────────────────────────────────────────────
		{
			ID:          "IDS-OPCUA-001",
			Title:       "OPC UA Write Detected",
			Description: "OPC UA Write service modifies server node values.",
			Proto:       "opcua",
			Severity:    "medium",
			Message:     "OPC UA write operation detected",
			When: IDSCondition{
				Field: "attr.messageType", Op: "equals", Value: "Write",
			},
			Labels: map[string]string{"mitre": "T0855", "category": "ics"},
		},
	}
}
