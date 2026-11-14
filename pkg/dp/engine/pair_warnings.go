// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"reflect"
)

func pairingCutoverWarnings(snap *rules.Snapshot) []enforce.RuleWarning {
	if snap == nil {
		return nil
	}
	var out []enforce.RuleWarning
	for _, entry := range snap.Firewall {
		protocol := entry.ICS.Protocol
		if rules.MonitorICS(entry, snap.DPIMode) || protocol != "modbus" && protocol != "dnp3" && protocol != "iec104" {
			continue
		}
		if !hasExplicitRequestAllow(snap, entry) {
			out = append(out, enforce.RuleWarning{RuleID: entry.ID, Action: entry.Action, Predicate: enforce.PredicateInspection,
				Message: "This enforce scope has no explicit ICS request ALLOW covering its transport, identity and schedule scope. Default or protocol-less ALLOW cannot mint request grants; requests without an explicit ICS permit are non-admitted and the session is reset."})
		}
		if entry.Action != rules.ActionAllow {
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

func hasExplicitRequestAllow(snap *rules.Snapshot, scope rules.Entry) bool {
	for _, allow := range snap.Firewall {
		if allow.Action != rules.ActionAllow || allow.ICS.Protocol != scope.ICS.Protocol ||
			rules.MonitorICS(allow, snap.DPIMode) || allow.ICS.MessageClass != "" || allow.ICS.Direction == "response" {
			continue
		}
		if allow.HasIdentityPredicate() && !reflect.DeepEqual(allow.Identities, scope.Identities) ||
			allow.HasSchedulePredicate() && !reflect.DeepEqual(allow.Schedule, scope.Schedule) {
			continue
		}
		if enforce.TransportScopeCovers(allow, scope) {
			return true
		}
	}
	return false
}
