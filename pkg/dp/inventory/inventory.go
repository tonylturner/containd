// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package inventory

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

// DiscoveredAsset represents an ICS device discovered from observed traffic.
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

// Inventory maintains a thread-safe map of discovered ICS assets.
type Inventory struct {
	mu     sync.RWMutex
	assets map[string]*DiscoveredAsset
}

// New creates a new empty Inventory.
func New() *Inventory {
	return &Inventory{
		assets: make(map[string]*DiscoveredAsset),
	}
}

// RecordEvent extracts ICS metadata from a DPI event and updates the
// inventory for both source and destination IPs.
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

	// Source is the master (sends requests).
	src := inv.getOrCreate(srcIP, "modbus", now)
	src.Role = "master"
	src.LastSeen = now
	src.PacketCount++
	src.FunctionCodes = addUint8Unique(src.FunctionCodes, fc)
	src.UnitIDs = addUint8Unique(src.UnitIDs, unitID)
	src.Peers = addStringUnique(src.Peers, dstIP)

	// Destination is the slave (receives requests).
	dst := inv.getOrCreate(dstIP, "modbus", now)
	dst.Role = "slave"
	dst.LastSeen = now
	dst.PacketCount++
	dst.FunctionCodes = addUint8Unique(dst.FunctionCodes, fc)
	dst.UnitIDs = addUint8Unique(dst.UnitIDs, unitID)
	dst.Peers = addStringUnique(dst.Peers, srcIP)
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

	src := inv.getOrCreate(srcIP, "dnp3", now)
	src.Role = "master"
	src.LastSeen = now
	src.PacketCount++
	src.FunctionCodes = addUint8Unique(src.FunctionCodes, fc)
	src.StationAddresses = addUint16Unique(src.StationAddresses, srcAddr)
	src.Peers = addStringUnique(src.Peers, dstIP)

	dst := inv.getOrCreate(dstIP, "dnp3", now)
	dst.Role = "slave"
	dst.LastSeen = now
	dst.PacketCount++
	dst.FunctionCodes = addUint8Unique(dst.FunctionCodes, fc)
	dst.StationAddresses = addUint16Unique(dst.StationAddresses, dstAddr)
	dst.Peers = addStringUnique(dst.Peers, srcIP)
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

	src := inv.getOrCreate(srcIP, "cip", now)
	src.Role = "client"
	src.LastSeen = now
	src.PacketCount++
	src.FunctionCodes = addUint8Unique(src.FunctionCodes, sc)
	src.Peers = addStringUnique(src.Peers, dstIP)

	dst := inv.getOrCreate(dstIP, "cip", now)
	dst.Role = "server"
	dst.LastSeen = now
	dst.PacketCount++
	dst.FunctionCodes = addUint8Unique(dst.FunctionCodes, sc)
	dst.Peers = addStringUnique(dst.Peers, srcIP)
}

// getOrCreate returns the existing asset or creates a new one. Must be called with inv.mu held.
func (inv *Inventory) getOrCreate(ip, protocol string, now time.Time) *DiscoveredAsset {
	a, ok := inv.assets[ip]
	if !ok {
		a = &DiscoveredAsset{
			IP:        ip,
			Protocol:  protocol,
			FirstSeen: now,
			LastSeen:  now,
		}
		inv.assets[ip] = a
	}
	return a
}

// List returns all discovered assets sorted by IP.
func (inv *Inventory) List() []DiscoveredAsset {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	out := make([]DiscoveredAsset, 0, len(inv.assets))
	for _, a := range inv.assets {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].IP < out[j].IP
	})
	return out
}

// Get returns the discovered asset for a specific IP, if any.
func (inv *Inventory) Get(ip string) (*DiscoveredAsset, bool) {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	a, ok := inv.assets[ip]
	if !ok {
		return nil, false
	}
	cp := *a
	return &cp, true
}

// Clear resets the inventory.
func (inv *Inventory) Clear() {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	inv.assets = make(map[string]*DiscoveredAsset)
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

// addUint16Unique appends v to slice if not already present.
func addUint16Unique(s []uint16, v uint16) []uint16 {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// addStringUnique appends v to slice if not already present.
func addStringUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
