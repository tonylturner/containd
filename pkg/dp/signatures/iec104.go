// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package signatures

// iec104Signatures are the IEC 60870-5-104 built-ins (spec §7.4). They
// alert; they never reset. The command signatures match client control
// requests only, not their confirmations (direction response).
func iec104Signatures() []Signature {
	return []Signature{
		{
			ID:          "IEC104-CONTROL-CMD",
			Name:        "IEC 104 Control Command",
			Description: "A client sent an IEC 104 control command (select or execute) to a CA/IOA.",
			Severity:    "high",
			Protocol:    "iec104",
			Conditions: []Condition{
				{Field: "kind", Op: "equals", Value: "request"},
				{Field: "class", Op: "equals", Value: "control"},
			},
			References: []string{"https://attack.mitre.org/techniques/T0855/"},
		},
		{
			ID:          "IEC104-SELECT",
			Name:        "IEC 104 Select Before Operate",
			Description: "A client sent the select step of an IEC 104 select-before-operate command.",
			Severity:    "medium",
			Protocol:    "iec104",
			Conditions: []Condition{
				{Field: "kind", Op: "equals", Value: "request"},
				{Field: "select", Op: "equals", Value: true},
			},
			References: []string{"https://attack.mitre.org/techniques/T0855/"},
		},
		{
			ID:          "IEC104-SYSTEM-CMD",
			Name:        "IEC 104 Clock Sync, Reset Process or Test Command",
			Description: "A client sent an IEC 104 clock synchronization (103), reset process (105) or test with time (107) command.",
			Severity:    "high",
			Protocol:    "iec104",
			Conditions: []Condition{
				{Field: "kind", Op: "equals", Value: "request"},
				{Field: "type_id", Op: "in", Value: []any{float64(103), float64(105), float64(107)}},
			},
			References: []string{"https://attack.mitre.org/techniques/T0816/"},
		},
		{
			ID:          "IEC104-BROADCAST",
			Name:        "IEC 104 Broadcast Address",
			Description: "An IEC 104 I-frame addressed the broadcast common address 65535.",
			Severity:    "high",
			Protocol:    "iec104",
			Conditions: []Condition{
				{Field: "ca", Op: "equals", Value: float64(65535)},
			},
			References: []string{"https://attack.mitre.org/techniques/T0855/"},
		},
		{
			ID:          "IEC104-STOPDT",
			Name:        "IEC 104 STOPDT",
			Description: "An IEC 104 STOPDT act stops data transfer on the session; monitoring goes stale.",
			Severity:    "medium",
			Protocol:    "iec104",
			Conditions: []Condition{
				{Field: "u_function", Op: "equals", Value: "stopdt_act"},
			},
			References: []string{"https://attack.mitre.org/techniques/T0814/"},
		},
		{
			ID:          "IEC104-MALFORMED",
			Name:        "IEC 104 Malformed APDU",
			Description: "An IEC 104 APDU violates the framing, layout, B profile or role rules.",
			Severity:    "medium",
			Protocol:    "iec104",
			Conditions: []Condition{
				{Field: "kind", Op: "equals", Value: "malformed"},
			},
			References: []string{"https://attack.mitre.org/techniques/T0814/"},
		},
		{
			ID:          "IEC104-UNSUPPORTED",
			Name:        "IEC 104 Unsupported Type",
			Description: "An IEC 104 ASDU carries a Type ID outside the B profile.",
			Severity:    "low",
			Protocol:    "iec104",
			Conditions: []Condition{
				{Field: "kind", Op: "equals", Value: "unsupported"},
			},
			References: []string{"https://attack.mitre.org/techniques/T0846/"},
		},
	}
}
