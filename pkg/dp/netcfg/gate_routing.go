// SPDX-License-Identifier: Apache-2.0
package netcfg

// The scanning gate delivers packets it marks to its local transparent
// listeners through one policy rule and one local route per address family:
//
//	ip rule add priority 1 fwmark 0x400000/0x400000 lookup 104010 protocol 100
//	ip route add local default dev lo table 104010 protocol 100
//
// EnsureGateRouting and RemoveGateRouting own exactly those objects. The gate
// manager identifies them by these constants.
const (
	// GateLocalMark is the packet mark bit the gate ruleset sets on packets
	// that must be delivered to this host instead of being forwarded.
	GateLocalMark uint32 = 0x00400000
	// GateRoutingTable holds the local default route for marked packets. Like
	// ManagementTable it lies outside the 1..252 range of configurable tables.
	GateRoutingTable uint32 = 104010
	// GateRulePriority places the gate rule directly after the kernel
	// local-table rule, beside the management pin.
	GateRulePriority uint32 = 1
	// GateRouteProtocol marks gate rules and routes so they can be reconciled
	// without touching containd routes (98), the management pin (99) or any
	// protocol number iproute2 names.
	GateRouteProtocol uint8 = 100
)
