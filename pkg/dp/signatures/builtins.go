// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package signatures

// builtinSignatures returns the set of built-in ICS threat signatures.
func builtinSignatures() []Signature {
	return []Signature{
		// ---- Modbus ----
		{
			ID:          "MODBUS-SCAN-001",
			Name:        "Modbus Broadcast Scan",
			Description: "Modbus broadcast to unit_id 0 with diagnostic function code, indicative of device scanning.",
			Severity:    "medium",
			Protocol:    "modbus",
			Conditions: []Condition{
				{Field: "unit_id", Op: "equals", Value: float64(0)},
				{Field: "function_code", Op: "in", Value: []any{float64(8), float64(43)}},
			},
			References: []string{"https://attack.mitre.org/techniques/T0846/"},
		},
		{
			ID:          "MODBUS-FORCE-001",
			Name:        "Modbus Force Listen Only Mode",
			Description: "Diagnostics function code 8, sub-function 4: forces device into listen-only mode, disrupting communications.",
			Severity:    "high",
			Protocol:    "modbus",
			Conditions: []Condition{
				{Field: "function_code", Op: "equals", Value: float64(8)},
				{Field: "sub_function", Op: "equals", Value: float64(4)},
			},
			References: []string{"https://attack.mitre.org/techniques/T0814/"},
		},
		{
			ID:          "MODBUS-RESTART-001",
			Name:        "Modbus Restart Communications",
			Description: "Diagnostics function code 8, sub-function 1: restarts communications port, potential DoS.",
			Severity:    "high",
			Protocol:    "modbus",
			Conditions: []Condition{
				{Field: "function_code", Op: "equals", Value: float64(8)},
				{Field: "sub_function", Op: "equals", Value: float64(1)},
			},
			References: []string{"https://attack.mitre.org/techniques/T0814/"},
		},
		{
			ID:          "MODBUS-WRITE-COIL-ALL",
			Name:        "Modbus Mass Coil Write",
			Description: "Write Multiple Coils (FC 15) with quantity > 1000, potentially overwriting all device outputs.",
			Severity:    "critical",
			Protocol:    "modbus",
			Conditions: []Condition{
				{Field: "function_code", Op: "equals", Value: float64(15)},
				{Field: "quantity", Op: "gt", Value: float64(1000)},
			},
			References: []string{"https://attack.mitre.org/techniques/T0855/"},
		},
		{
			ID:          "MODBUS-EXCEPTION-STORM",
			Name:        "Modbus Exception Response Storm",
			Description: "Exception response (function code >= 128) may indicate scanning or brute-force activity.",
			Severity:    "medium",
			Protocol:    "modbus",
			Conditions: []Condition{
				{Field: "function_code", Op: "gte", Value: float64(128)},
			},
			References: []string{"https://attack.mitre.org/techniques/T0846/"},
		},

		// ---- DNP3 ----
		{
			ID:          "DNP3-COLD-RESTART",
			Name:        "DNP3 Cold Restart",
			Description: "DNP3 cold restart command (function code 13) causes full device reboot.",
			Severity:    "critical",
			Protocol:    "dnp3",
			Conditions: []Condition{
				{Field: "function_code", Op: "equals", Value: float64(13)},
			},
			References: []string{"https://attack.mitre.org/techniques/T0816/"},
		},
		{
			ID:          "DNP3-WARM-RESTART",
			Name:        "DNP3 Warm Restart",
			Description: "DNP3 warm restart command (function code 14) causes application restart.",
			Severity:    "high",
			Protocol:    "dnp3",
			Conditions: []Condition{
				{Field: "function_code", Op: "equals", Value: float64(14)},
			},
			References: []string{"https://attack.mitre.org/techniques/T0816/"},
		},
		{
			ID:          "DNP3-STOP-APP",
			Name:        "DNP3 Stop Application",
			Description: "DNP3 stop application command (function code 18) halts the running application.",
			Severity:    "critical",
			Protocol:    "dnp3",
			Conditions: []Condition{
				{Field: "function_code", Op: "equals", Value: float64(18)},
			},
			References: []string{"https://attack.mitre.org/techniques/T0881/"},
		},
		{
			ID:          "DNP3-FILE-AUTH",
			Name:        "DNP3 File Authentication",
			Description: "DNP3 file authentication request (object group 70) may indicate unauthorized file access attempts.",
			Severity:    "high",
			Protocol:    "dnp3",
			Conditions: []Condition{
				{Field: "object_group", Op: "equals", Value: float64(70)},
			},
			References: []string{"https://attack.mitre.org/techniques/T0859/"},
		},

		// ---- CIP ----
		{
			ID:          "CIP-RESET-001",
			Name:        "CIP Reset Service",
			Description: "CIP Reset service (service code 0x05) can reset a device to factory defaults.",
			Severity:    "critical",
			Protocol:    "cip",
			Conditions: []Condition{
				{Field: "service_code", Op: "equals", Value: float64(0x05)},
			},
			References: []string{"https://attack.mitre.org/techniques/T0816/"},
		},
		{
			ID:          "CIP-STOP-001",
			Name:        "CIP PLC Stop/Run Change",
			Description: "CIP service targeting PLC run/stop state change (service code 0x07).",
			Severity:    "critical",
			Protocol:    "cip",
			Conditions: []Condition{
				{Field: "service_code", Op: "equals", Value: float64(0x07)},
			},
			References: []string{"https://attack.mitre.org/techniques/T0881/"},
		},

		// ---- S7comm ----
		{
			ID:          "S7-PLC-STOP",
			Name:        "S7comm PLC Stop",
			Description: "S7comm PLC Stop command (function code 0x29) halts the PLC program.",
			Severity:    "critical",
			Protocol:    "s7comm",
			Conditions: []Condition{
				{Field: "function_code", Op: "equals", Value: float64(0x29)},
			},
			References: []string{"https://attack.mitre.org/techniques/T0881/"},
		},
		{
			ID:          "S7-PLC-CONTROL",
			Name:        "S7comm PLC Control",
			Description: "S7comm PLC Control command (function code 0x28) can start/stop PLC programs.",
			Severity:    "high",
			Protocol:    "s7comm",
			Conditions: []Condition{
				{Field: "function_code", Op: "equals", Value: float64(0x28)},
			},
			References: []string{"https://attack.mitre.org/techniques/T0858/"},
		},
		{
			ID:          "S7-DOWNLOAD",
			Name:        "S7comm Block Download",
			Description: "S7comm block download (function codes 0x1A-0x1C) may indicate firmware modification.",
			Severity:    "critical",
			Protocol:    "s7comm",
			Conditions: []Condition{
				{Field: "function_code", Op: "in", Value: []any{float64(0x1A), float64(0x1B), float64(0x1C)}},
			},
			References: []string{"CVE-2019-13945", "https://attack.mitre.org/techniques/T0839/"},
		},

		// ---- Cross-protocol ----
		{
			ID:          "ICS-WRITE-STORM",
			Name:        "ICS Write Storm",
			Description: "High rate of write operations detected across ICS protocol, possible attack or misconfiguration.",
			Severity:    "high",
			Protocol:    "",
			Conditions: []Condition{
				{Field: "is_write", Op: "equals", Value: true},
			},
			References: []string{"https://attack.mitre.org/techniques/T0855/"},
		},
	}
}
