// SPDX-License-Identifier: Apache-2.0

package protection

import "strconv"

type SubsystemName string

const (
	SubsystemConfig       SubsystemName = "config"
	SubsystemNFT          SubsystemName = "nft"
	SubsystemInterfaces   SubsystemName = "interfaces"
	SubsystemRouting      SubsystemName = "routing"
	SubsystemForwarding   SubsystemName = "forwarding"
	SubsystemIECEnvelope  SubsystemName = "iec-envelope"
	SubsystemScanGate     SubsystemName = "scan-gate"
	SubsystemScanner      SubsystemName = "scanner"
	SubsystemTrust        SubsystemName = "trust"
	SubsystemOpenVPN      SubsystemName = "openvpn"
	SubsystemWireGuard    SubsystemName = "wireguard"
	SubsystemForwardProxy SubsystemName = "forward-proxy"
	SubsystemReverseProxy SubsystemName = "reverse-proxy"
	SubsystemAV           SubsystemName = "av"
	SubsystemDNS          SubsystemName = "dns"
	SubsystemNTP          SubsystemName = "ntp"
	SubsystemSyslog       SubsystemName = "syslog"
	SubsystemDHCP         SubsystemName = "dhcp"
)

// Selection describes original desired policy dependencies, never a quarantined
// projection. Traffic services always require apply or verified stop, including
// unknown prior runtime after restart. Unselected AV is delivery-only.
type Selection struct {
	Forwarding  bool
	NFQueues    []uint16
	IECEnvelope bool
	Scan        bool
	Trust       bool
}

// Requirement is a detached row of the fixed delivery table.
type Requirement struct {
	Name      SubsystemName
	Owner     Owner
	Required  bool
	AllowStop bool // services can prove absence; prerequisites must prove apply
}

type condition uint8

const (
	always condition = iota
	forwarding
	envelope
	scan
	trust
	never
)

// The sole required-set authority: enforcement plus traffic-carrying services.
// Logging/schedule degradation is an existing engine/management health override,
// not an extra delivery owner. PCAP, evidence and management liveness are outside
// this ledger and can never satisfy or gate its delivery obligations.
var requiredSet = [...]struct {
	name  SubsystemName
	owner Owner
	when  condition
	stop  bool
}{
	{SubsystemConfig, OwnerEngine, always, false},
	{SubsystemNFT, OwnerEngine, always, false},
	{SubsystemInterfaces, OwnerEngine, always, false},
	{SubsystemRouting, OwnerEngine, always, false},
	{SubsystemForwarding, OwnerEngine, forwarding, false},
	{SubsystemIECEnvelope, OwnerEngine, envelope, false},
	{SubsystemScanGate, OwnerEngine, scan, false},
	{SubsystemScanner, OwnerEngine, scan, false},
	{SubsystemTrust, OwnerEngine, trust, false},
	{SubsystemOpenVPN, OwnerManagement, always, true},
	{SubsystemWireGuard, OwnerEngine, always, true},
	{SubsystemForwardProxy, OwnerManagement, always, true},
	{SubsystemReverseProxy, OwnerManagement, always, true},
	{SubsystemAV, OwnerManagement, never, true},
	{SubsystemDNS, OwnerManagement, never, true},
	{SubsystemNTP, OwnerManagement, never, true},
	{SubsystemSyslog, OwnerManagement, never, true},
	{SubsystemDHCP, OwnerEngine, never, true},
}

// NFQueueName preserves the engine's stable per-queue component name.
func NFQueueName(queue uint16) SubsystemName {
	return SubsystemName("nfqueue:" + strconv.FormatUint(uint64(queue), 10))
}

// Requirements returns a fresh table; there is no runtime required-set switch.
// Queue zero and duplicate selections are invalid and Reduce rejects them.
func Requirements(s Selection) []Requirement {
	out := make([]Requirement, 0, len(requiredSet)+len(s.NFQueues))
	for _, row := range requiredSet {
		required := row.when == always ||
			row.when == forwarding && s.Forwarding ||
			row.when == envelope && s.IECEnvelope ||
			row.when == scan && s.Scan ||
			row.when == trust && s.Trust
		out = append(out, Requirement{row.name, row.owner, required, row.stop})
	}
	for _, queue := range s.NFQueues {
		out = append(out, Requirement{NFQueueName(queue), OwnerEngine, true, false})
	}
	return out
}
