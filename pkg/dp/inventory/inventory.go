// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package inventory

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// DiscoveredAsset represents one IP, protocol and role observation from ICS traffic.
type DiscoveredAsset struct {
	IP               string    `json:"ip"`
	Protocol         string    `json:"protocol"`
	Role             string    `json:"role"`
	UnitIDs          []uint8   `json:"unitIds,omitempty"`
	FunctionCodes    []uint8   `json:"functionCodes,omitempty"`
	StationAddresses []uint16  `json:"stationAddresses,omitempty"`
	FirstSeen        time.Time `json:"firstSeen"`
	LastSeen         time.Time `json:"lastSeen"`
	PacketCount      int       `json:"packetCount"`
	Peers            []string  `json:"peers,omitempty"`
}

type assetKey struct {
	IP       string
	Protocol string
	Role     string
}

// Inventory maintains bounded, thread-safe legacy assets and a separately
// synchronized passive IEC 104 inventory. Construct it with New.
type Inventory struct {
	mu       sync.RWMutex
	assets   *bounded[assetKey, *DiscoveredAsset]
	overflow InventoryOverflow
	iec104   iec104Store
}

// New creates a new empty Inventory.
func New() *Inventory {
	return &Inventory{
		assets: newBounded[assetKey, *DiscoveredAsset](MaxAssets),
		iec104: newIEC104Store(),
	}
}

// RecordEvent extracts ICS metadata from a DPI event and updates the
// inventory for both wire IPs. Roles use the connection direction retained in
// FlowID, never the event kind (which may be exception, restart or session).
func (inv *Inventory) RecordEvent(srcIP, dstIP string, ev dpi.Event) {
	proto := strings.ToLower(ev.Proto)
	switch proto {
	case "modbus":
		inv.recordModbus(srcIP, dstIP, ev)
	case "dnp3":
		inv.recordDNP3(srcIP, dstIP, ev)
	case "cip":
		inv.recordCIP(srcIP, dstIP, ev)
	default:
		return
	}
}

func (inv *Inventory) recordModbus(srcIP, dstIP string, ev dpi.Event) {
	now := ev.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var unitID uint8
	var fc uint8
	if v, ok := ev.Attributes["unit_id"].(uint8); ok {
		unitID = v
	}
	if v, ok := ev.Attributes["function_code"].(uint8); ok {
		fc = v
	}

	inv.mu.Lock()
	defer inv.mu.Unlock()

	srcRole, dstRole := eventRoles(srcIP, dstIP, ev, "master", "slave")
	src := inv.getOrCreate(srcIP, "modbus", srcRole, now)
	src.LastSeen = now
	src.PacketCount++
	src.FunctionCodes = addUint8Unique(src.FunctionCodes, fc)
	src.UnitIDs = addUint8Unique(src.UnitIDs, unitID)
	src.Peers = inv.addPeer(src.Peers, dstIP)

	dst := inv.getOrCreate(dstIP, "modbus", dstRole, now)
	dst.LastSeen = now
	dst.PacketCount++
	dst.FunctionCodes = addUint8Unique(dst.FunctionCodes, fc)
	dst.UnitIDs = addUint8Unique(dst.UnitIDs, unitID)
	dst.Peers = inv.addPeer(dst.Peers, srcIP)
}

func (inv *Inventory) recordDNP3(srcIP, dstIP string, ev dpi.Event) {
	now := ev.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var fc uint8
	var srcAddr, dstAddr uint16
	if v, ok := ev.Attributes["function_code"].(uint8); ok {
		fc = v
	}
	if v, ok := ev.Attributes["source_address"].(uint16); ok {
		srcAddr = v
	}
	if v, ok := ev.Attributes["destination_address"].(uint16); ok {
		dstAddr = v
	}

	inv.mu.Lock()
	defer inv.mu.Unlock()

	srcRole, dstRole := eventRoles(srcIP, dstIP, ev, "master", "slave")
	src := inv.getOrCreate(srcIP, "dnp3", srcRole, now)
	src.LastSeen = now
	src.PacketCount++
	src.FunctionCodes = addUint8Unique(src.FunctionCodes, fc)
	src.StationAddresses = inv.addStationAddress(src.StationAddresses, srcAddr)
	src.Peers = inv.addPeer(src.Peers, dstIP)

	dst := inv.getOrCreate(dstIP, "dnp3", dstRole, now)
	dst.LastSeen = now
	dst.PacketCount++
	dst.FunctionCodes = addUint8Unique(dst.FunctionCodes, fc)
	dst.StationAddresses = inv.addStationAddress(dst.StationAddresses, dstAddr)
	dst.Peers = inv.addPeer(dst.Peers, srcIP)
}

func (inv *Inventory) recordCIP(srcIP, dstIP string, ev dpi.Event) {
	now := ev.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var sc uint8
	if v, ok := ev.Attributes["service_code"].(uint8); ok {
		sc = v
	}

	inv.mu.Lock()
	defer inv.mu.Unlock()

	srcRole, dstRole := eventRoles(srcIP, dstIP, ev, "client", "server")
	src := inv.getOrCreate(srcIP, "cip", srcRole, now)
	src.LastSeen = now
	src.PacketCount++
	src.FunctionCodes = addUint8Unique(src.FunctionCodes, sc)
	src.Peers = inv.addPeer(src.Peers, dstIP)

	dst := inv.getOrCreate(dstIP, "cip", dstRole, now)
	dst.LastSeen = now
	dst.PacketCount++
	dst.FunctionCodes = addUint8Unique(dst.FunctionCodes, sc)
	dst.Peers = inv.addPeer(dst.Peers, srcIP)
}

func eventRoles(srcIP, dstIP string, ev dpi.Event, initiator, responder string) (string, string) {
	key, ok := flow.ParseKey(ev.FlowID)
	if !ok || key.SrcIP.String() != srcIP || key.DstIP.String() != dstIP {
		return "", "" // No connection evidence: do not invent or erase roles.
	}
	if key.Dir == flow.DirReverse {
		return responder, initiator
	}
	return initiator, responder
}

// getOrCreate returns one observation bucket. Must be called with inv.mu held.
func (inv *Inventory) getOrCreate(ip, protocol, role string, now time.Time) *DiscoveredAsset {
	key := assetKey{IP: ip, Protocol: protocol, Role: role}
	return inv.assets.observe(key, time.Now(), func() *DiscoveredAsset {
		return &DiscoveredAsset{IP: ip, Protocol: protocol, Role: role, FirstSeen: now, LastSeen: now}
	}, &inv.overflow.Assets)
}

// List returns all discovered observations sorted by IP, protocol and role.
func (inv *Inventory) List() []DiscoveredAsset {
	return inv.snapshot(nil)
}

// GetAssets returns all observations for an IP, sorted by protocol and role.
// An empty slice means no observations remain for that IP.
func (inv *Inventory) GetAssets(ip string) []DiscoveredAsset {
	return inv.snapshot(func(key assetKey) bool { return key.IP == ip })
}

func (inv *Inventory) snapshot(match func(assetKey) bool) []DiscoveredAsset {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	inv.assets.expire(time.Now())
	out := make([]DiscoveredAsset, 0)
	for key, e := range inv.assets.items {
		if match == nil || match(key) {
			out = append(out, cloneAsset(e.Value.(*entry[assetKey, *DiscoveredAsset]).value))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IP != out[j].IP {
			return out[i].IP < out[j].IP
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].Role < out[j].Role
	})
	return out
}

// Clear resets both inventories and their overflow counters.
func (inv *Inventory) Clear() {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	inv.assets = newBounded[assetKey, *DiscoveredAsset](MaxAssets)
	inv.overflow = InventoryOverflow{}
	inv.iec104.mu.Lock()
	inv.iec104.pairs = newBounded[pairKey, *pairState](MaxIEC104Pairs)
	inv.iec104.overflow = InventoryOverflow{}
	inv.iec104.busyObservations.Store(0)
	inv.iec104.busyOutcomes.Store(0)
	inv.iec104.mu.Unlock()
}

// addUint8Unique appends v to slice if not already present.
func addUint8Unique(s []uint8, v uint8) []uint8 {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// addStationAddress bounds the otherwise unbounded DNP3 address list.
func (inv *Inventory) addStationAddress(s []uint16, v uint16) []uint16 {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	if len(s) == MaxStationAddresses {
		inv.overflow.StationAddresses++
		return s
	}
	return append(s, v)
}

func (inv *Inventory) addPeer(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	if len(s) == MaxPeers {
		inv.overflow.Peers++
		return s
	}
	return append(s, v)
}

func cloneAsset(a *DiscoveredAsset) DiscoveredAsset {
	cp := *a
	cp.UnitIDs = append([]uint8(nil), a.UnitIDs...)
	cp.FunctionCodes = append([]uint8(nil), a.FunctionCodes...)
	cp.StationAddresses = append([]uint16(nil), a.StationAddresses...)
	cp.Peers = append([]string(nil), a.Peers...)
	return cp
}
