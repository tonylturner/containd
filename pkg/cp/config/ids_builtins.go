// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

// DefaultIDSConfig returns the IDS configuration with built-in rules enabled.
// These rules ship with containd and cover common ICS protocol abuse, IT
// network threats, and cross-protocol anomalies. Users can add custom rules
// or import Sigma rules on top of these via the UI or API.
func DefaultIDSConfig() IDSConfig {
	return IDSConfig{
		Enabled: true,
		Rules:   builtinIDSRules(),
	}
}

func builtinIDSRules() []IDSRule {
	return []IDSRule{
		// ════════════════════════════════════════════════════════════
		// ICS Protocol Abuse
		// ════════════════════════════════════════════════════════════

		// ── Modbus ─────────────────────────────────────────────────
		{
			ID:          "IDS-MODBUS-001",
			Title:       "Modbus Unauthorized Write",
			Description: "Write Single/Multiple Coils or Registers (FC 5,6,15,16) detected.",
			Proto:       "modbus",
			Severity:    "high",
			Message:     "Modbus write operation detected",
			When: IDSCondition{
				Field: "attr.function_code", Op: "in", Value: []any{float64(5), float64(6), float64(15), float64(16)},
			},
			Labels: map[string]string{"mitre": "T0855", "category": "ics"},
		},
		{
			ID:          "IDS-MODBUS-002",
			Title:       "Modbus Diagnostic Command",
			Description: "Diagnostics function (FC 8) can disrupt device communications or force listen-only mode.",
			Proto:       "modbus",
			Severity:    "high",
			Message:     "Modbus diagnostic function detected",
			When: IDSCondition{
				Field: "attr.function_code", Op: "equals", Value: float64(8),
			},
			Labels: map[string]string{"mitre": "T0814", "category": "ics"},
		},
		{
			ID:          "IDS-MODBUS-003",
			Title:       "Modbus Program Upload/Download",
			Description: "Read/Write File Record (FC 20,21) may indicate firmware extraction or modification.",
			Proto:       "modbus",
			Severity:    "critical",
			Message:     "Modbus file record access detected",
			When: IDSCondition{
				Field: "attr.function_code", Op: "in", Value: []any{float64(20), float64(21)},
			},
			Labels: map[string]string{"mitre": "T0843", "category": "ics"},
		},
		{
			ID:          "IDS-MODBUS-004",
			Title:       "Modbus Exception Response",
			Description: "Exception response (FC >= 128) may indicate scanning, fuzzing, or unauthorized access attempts.",
			Proto:       "modbus",
			Severity:    "medium",
			Message:     "Modbus exception response observed",
			When: IDSCondition{
				Field: "attr.function_code", Op: "gt", Value: float64(127),
			},
			Labels: map[string]string{"mitre": "T0846", "category": "ics"},
		},

		// ── DNP3 ──────────────────────────────────────────────────
		{
			ID:          "IDS-DNP3-001",
			Title:       "DNP3 Cold/Warm Restart",
			Description: "Cold restart (FC 13) or warm restart (FC 14) can cause device outage.",
			Proto:       "dnp3",
			Severity:    "critical",
			Message:     "DNP3 restart command detected",
			When: IDSCondition{
				Field: "attr.function_code", Op: "in", Value: []any{float64(13), float64(14)},
			},
			Labels: map[string]string{"mitre": "T0816", "category": "ics"},
		},
		{
			ID:          "IDS-DNP3-002",
			Title:       "DNP3 Stop Application",
			Description: "Stop Application command (FC 18) halts the running RTU/PLC program.",
			Proto:       "dnp3",
			Severity:    "critical",
			Message:     "DNP3 stop application command detected",
			When: IDSCondition{
				Field: "attr.function_code", Op: "equals", Value: float64(18),
			},
			Labels: map[string]string{"mitre": "T0881", "category": "ics"},
		},
		{
			ID:          "IDS-DNP3-003",
			Title:       "DNP3 Direct Operate No Ack",
			Description: "Direct Operate No Ack (FC 5) bypasses select-before-operate safety pattern.",
			Proto:       "dnp3",
			Severity:    "high",
			Message:     "DNP3 direct operate without acknowledgment",
			When: IDSCondition{
				Field: "attr.function_code", Op: "equals", Value: float64(5),
			},
			Labels: map[string]string{"mitre": "T0855", "category": "ics"},
		},

		// ── EtherNet/IP CIP ───────────────────────────────────────
		{
			ID:          "IDS-CIP-001",
			Title:       "CIP Reset Service",
			Description: "CIP Reset (service 0x05) restores factory defaults — potential sabotage.",
			Proto:       "enip",
			Severity:    "critical",
			Message:     "CIP reset service invoked",
			When: IDSCondition{
				Field: "attr.service_code", Op: "equals", Value: float64(0x05),
			},
			Labels: map[string]string{"mitre": "T0816", "category": "ics"},
		},
		{
			ID:          "IDS-CIP-002",
			Title:       "CIP PLC Mode Change",
			Description: "CIP service 0x07 changes PLC run/stop state.",
			Proto:       "enip",
			Severity:    "critical",
			Message:     "CIP PLC run/stop state change",
			When: IDSCondition{
				Field: "attr.service_code", Op: "equals", Value: float64(0x07),
			},
			Labels: map[string]string{"mitre": "T0881", "category": "ics"},
		},

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

		// ════════════════════════════════════════════════════════════
		// IT Network Threats
		// ════════════════════════════════════════════════════════════

		// ── DNS ───────────────────────────────────────────────────
		{
			ID:          "IDS-DNS-001",
			Title:       "DNS Zone Transfer Attempt",
			Description: "AXFR/IXFR query type indicates zone transfer — potential reconnaissance.",
			Proto:       "dns",
			Severity:    "high",
			Message:     "DNS zone transfer attempt detected",
			When: IDSCondition{
				Field: "attr.type", Op: "in", Value: []any{"AXFR", "IXFR"},
			},
			Labels: map[string]string{"mitre": "T1590", "category": "recon"},
		},
		{
			ID:          "IDS-DNS-002",
			Title:       "DNS TXT Record Query",
			Description: "TXT queries may indicate DNS tunneling or C2 communication.",
			Proto:       "dns",
			Severity:    "medium",
			Message:     "DNS TXT record query observed",
			When: IDSCondition{
				Field: "attr.type", Op: "equals", Value: "TXT",
			},
			Labels: map[string]string{"mitre": "T1071.004", "category": "c2"},
		},

		// ── TLS ───────────────────────────────────────────────────
		{
			ID:          "IDS-TLS-001",
			Title:       "TLS Version Downgrade",
			Description: "TLS connection using version below 1.2 may indicate downgrade attack or legacy client.",
			Proto:       "tls",
			Severity:    "medium",
			Message:     "TLS version below 1.2 detected",
			When: IDSCondition{
				Any: []IDSCondition{
					{Field: "attr.version", Op: "equals", Value: "TLS 1.0"},
					{Field: "attr.version", Op: "equals", Value: "TLS 1.1"},
					{Field: "attr.version", Op: "equals", Value: "SSL 3.0"},
				},
			},
			Labels: map[string]string{"mitre": "T1557", "category": "crypto"},
		},

		// ── SSH ───────────────────────────────────────────────────
		{
			ID:          "IDS-SSH-001",
			Title:       "SSH Password Authentication",
			Description: "Password auth is less secure than key-based and may indicate unauthorized access.",
			Proto:       "ssh",
			Severity:    "low",
			Message:     "SSH password authentication observed",
			When: IDSCondition{
				Field: "attr.auth", Op: "equals", Value: "password",
			},
			Labels: map[string]string{"category": "access"},
		},

		// ── SNMP ──────────────────────────────────────────────────
		{
			ID:          "IDS-SNMP-001",
			Title:       "SNMP Set Request",
			Description: "SNMP SetRequest can modify device configuration remotely.",
			Proto:       "snmp",
			Severity:    "medium",
			Message:     "SNMP set request detected",
			When: IDSCondition{
				Field: "attr.pduType", Op: "equals", Value: "SetRequest",
			},
			Labels: map[string]string{"mitre": "T0855", "category": "ics"},
		},
		{
			ID:          "IDS-SNMP-002",
			Title:       "SNMP v1/v2c (No Encryption)",
			Description: "SNMP v1/v2c transmits community strings in cleartext.",
			Proto:       "snmp",
			Severity:    "low",
			Message:     "Unencrypted SNMP version detected",
			When: IDSCondition{
				Field: "attr.version", Op: "in", Value: []any{"v1", "v2c"},
			},
			Labels: map[string]string{"category": "crypto"},
		},

		// ════════════════════════════════════════════════════════════
		// Cross-Protocol / Behavioral
		// ════════════════════════════════════════════════════════════
		{
			ID:          "IDS-FW-BLOCK-001",
			Title:       "Firewall Block Event",
			Description: "Traffic blocked by firewall policy — may indicate scanning or policy violation.",
			Kind:        "block",
			Severity:    "medium",
			Message:     "Blocked traffic detected",
			Labels:      map[string]string{"category": "policy"},
		},
		{
			ID:          "IDS-AV-001",
			Title:       "Antivirus Detection",
			Description: "Malware or suspicious content detected by the AV engine.",
			Kind:        "service.av.detected",
			Severity:    "critical",
			Message:     "Antivirus threat detected",
			Labels:      map[string]string{"mitre": "T0866", "category": "malware"},
		},
		{
			ID:          "IDS-TELNET-001",
			Title:       "Telnet Connection Attempt",
			Description: "Telnet transmits credentials in cleartext and should not be used in OT environments.",
			Severity:    "high",
			Message:     "Telnet connection attempt detected",
			When: IDSCondition{
				Field: "dstPort", Op: "equals", Value: float64(23),
			},
			Labels: map[string]string{"mitre": "T0886", "category": "access"},
		},
		{
			ID:          "IDS-RDP-001",
			Title:       "RDP Connection Detected",
			Description: "Remote Desktop to OT devices is a common lateral movement vector.",
			Proto:       "rdp",
			Severity:    "medium",
			Message:     "RDP connection detected",
			Labels:      map[string]string{"mitre": "T0886", "category": "lateral"},
		},
	}
}
