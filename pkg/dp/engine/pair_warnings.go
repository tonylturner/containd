// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func pairingCutoverWarnings(snap *rules.Snapshot) []enforce.RuleWarning {
	if snap == nil {
		return nil
	}
	var out []enforce.RuleWarning
	for _, entry := range snap.Firewall {
		protocol := entry.ICS.Protocol
		if entry.Action != rules.ActionAllow || rules.MonitorICS(entry, snap.DPIMode) || protocol != "modbus" && protocol != "dnp3" && protocol != "iec104" {
			continue
		}
		text := "Solicited replies require an allowed compatible request on the same observed TCP session; unmatched, expired or ambiguous replies reset the session."
		if entry.ICS.MessageClass == "" && (protocol == "dnp3" || protocol == "iec104") {
			text += " This classless ALLOW does not authorize autonomous or session traffic; those require explicit messageClass rules and a fresh connection."
		}
		out = append(out, enforce.RuleWarning{RuleID: entry.ID, Action: entry.Action, Predicate: enforce.PredicateInspection, Message: text})
	}
	return out
}
