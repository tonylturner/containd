// SPDX-License-Identifier: Apache-2.0

package replay

import "github.com/tonylturner/containd/pkg/dp/rules"

// DeriveDemoSnapshot retains operator ICS ids, actions and predicates, forcing
// observation-only evaluation. Non-ICS forwarding, NAT, admission and scanning
// authority are deliberately absent. IDS inputs remain the operator's immutable
// rule inputs. Parsing modes and signatures are separate processor settings,
// not fields of rules.Snapshot, and must be copied by the caller.
func DeriveDemoSnapshot(running *rules.Snapshot, zones []string) rules.Snapshot {
	snap := rules.Snapshot{DPIMode: "monitor", Default: rules.ActionAllow, ZoneIfaces: map[string][]string{}}
	topo := NewTopology(zones)
	for _, zone := range zones {
		snap.ZoneIfaces[zone] = []string{topo.Interface(zone)}
	}
	hasIEC := false
	ids := map[string]bool{}
	if running != nil {
		snap.Version = running.Version
		snap.IDS = running.IDS
		for _, entry := range running.Firewall {
			ids[entry.ID] = true
			if entry.ICS.Protocol == "" {
				continue
			}
			entry.ICS.Mode = "monitor"
			snap.Firewall = append(snap.Firewall, entry)
			hasIEC = hasIEC || entry.ICS.Protocol == "iec104"
		}
	}
	if !hasIEC {
		id := "demo-iec104-envelope"
		for ids[id] {
			id += "-"
		}
		snap.Firewall = append(snap.Firewall, rules.Entry{
			ID: id, Action: rules.ActionAllow,
			Protocols: []rules.Protocol{{Name: "tcp", Port: "2404"}},
			ICS:       rules.ICSPredicate{Protocol: "iec104", Mode: "monitor"},
		})
	}
	return snap
}
