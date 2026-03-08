// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package templates

import "github.com/tonylturner/containd/pkg/cp/config"

// Purdue Model zone names.
const (
	ZoneL0  = "L0-Process"
	ZoneL1  = "L1-BasicControl"
	ZoneL2  = "L2-Supervisory"
	ZoneL3  = "L3-Operations"
	ZoneL35 = "L3.5-DMZ"
	ZoneL4  = "L4-Enterprise"
	ZoneL5  = "L5-Internet"
)

// PurdueZones returns the set of Zone definitions used by the Purdue model
// baseline template.
func PurdueZones() []config.Zone {
	return []config.Zone{
		{Name: ZoneL0, Description: "Process – field devices, sensors, actuators"},
		{Name: ZoneL1, Description: "Basic Control – PLCs, RTUs, safety controllers"},
		{Name: ZoneL2, Description: "Supervisory – HMIs, SCADA servers, engineering workstations"},
		{Name: ZoneL3, Description: "Operations – site operations, historian, domain controllers"},
		{Name: ZoneL35, Description: "DMZ – demilitarised zone between IT and OT"},
		{Name: ZoneL4, Description: "Enterprise – corporate IT network"},
		{Name: ZoneL5, Description: "Internet – external / untrusted networks"},
	}
}

func init() {
	register(Template{
		Name:        "purdue-baseline",
		Description: "Purdue Model baseline – default deny with standard ICS zone segmentation (L0-L5)",
		Rules:       purdueRules(),
	})
}

func purdueRules() []config.Rule {
	return []config.Rule{
		// ── Default deny between all zones ──────────────────────────
		{
			ID:          "purdue-default-deny",
			Description: "Default deny between all Purdue zones",
			SourceZones: []string{ZoneL0, ZoneL1, ZoneL2, ZoneL3, ZoneL35, ZoneL4, ZoneL5},
			DestZones:   []string{ZoneL0, ZoneL1, ZoneL2, ZoneL3, ZoneL35, ZoneL4, ZoneL5},
			Action:      config.ActionDeny,
		},
		// ── L1 ↔ L0: basic control to process ──────────────────────
		{
			ID:          "purdue-l1-to-l0",
			Description: "Allow Basic Control (L1) to Process (L0)",
			SourceZones: []string{ZoneL1},
			DestZones:   []string{ZoneL0},
			Action:      config.ActionAllow,
		},
		{
			ID:          "purdue-l0-to-l1",
			Description: "Allow Process (L0) to Basic Control (L1)",
			SourceZones: []string{ZoneL0},
			DestZones:   []string{ZoneL1},
			Action:      config.ActionAllow,
		},
		// ── L2 ↔ L1: supervisory to basic control ──────────────────
		{
			ID:          "purdue-l2-to-l1",
			Description: "Allow Supervisory (L2) to Basic Control (L1)",
			SourceZones: []string{ZoneL2},
			DestZones:   []string{ZoneL1},
			Action:      config.ActionAllow,
		},
		{
			ID:          "purdue-l1-to-l2",
			Description: "Allow Basic Control (L1) to Supervisory (L2)",
			SourceZones: []string{ZoneL1},
			DestZones:   []string{ZoneL2},
			Action:      config.ActionAllow,
		},
		// ── L3 → L2: operations to supervisory (read-only direction) ─
		{
			ID:          "purdue-l3-to-l2",
			Description: "Allow Operations (L3) to Supervisory (L2) – read-only",
			SourceZones: []string{ZoneL3},
			DestZones:   []string{ZoneL2},
			Action:      config.ActionAllow,
		},
		// ── L4 ↔ L3.5: enterprise to DMZ only ──────────────────────
		{
			ID:          "purdue-l4-to-dmz",
			Description: "Allow Enterprise (L4) to DMZ (L3.5)",
			SourceZones: []string{ZoneL4},
			DestZones:   []string{ZoneL35},
			Action:      config.ActionAllow,
		},
		{
			ID:          "purdue-dmz-to-l4",
			Description: "Allow DMZ (L3.5) to Enterprise (L4)",
			SourceZones: []string{ZoneL35},
			DestZones:   []string{ZoneL4},
			Action:      config.ActionAllow,
		},
		// ── L3 ↔ L3.5: operations to DMZ ───────────────────────────
		{
			ID:          "purdue-l3-to-dmz",
			Description: "Allow Operations (L3) to DMZ (L3.5)",
			SourceZones: []string{ZoneL3},
			DestZones:   []string{ZoneL35},
			Action:      config.ActionAllow,
		},
		{
			ID:          "purdue-dmz-to-l3",
			Description: "Allow DMZ (L3.5) to Operations (L3)",
			SourceZones: []string{ZoneL35},
			DestZones:   []string{ZoneL3},
			Action:      config.ActionAllow,
		},
		// ── Block L4 → L2/L1/L0: enterprise must never reach control ─
		{
			ID:          "purdue-block-l4-to-l2",
			Description: "Block Enterprise (L4) to Supervisory (L2)",
			SourceZones: []string{ZoneL4},
			DestZones:   []string{ZoneL2},
			Action:      config.ActionDeny,
		},
		{
			ID:          "purdue-block-l4-to-l1",
			Description: "Block Enterprise (L4) to Basic Control (L1)",
			SourceZones: []string{ZoneL4},
			DestZones:   []string{ZoneL1},
			Action:      config.ActionDeny,
		},
		{
			ID:          "purdue-block-l4-to-l0",
			Description: "Block Enterprise (L4) to Process (L0)",
			SourceZones: []string{ZoneL4},
			DestZones:   []string{ZoneL0},
			Action:      config.ActionDeny,
		},
		// ── Block L5 → everything except L4 ─────────────────────────
		{
			ID:          "purdue-block-l5-to-ot",
			Description: "Block Internet (L5) to all OT zones",
			SourceZones: []string{ZoneL5},
			DestZones:   []string{ZoneL0, ZoneL1, ZoneL2, ZoneL3, ZoneL35},
			Action:      config.ActionDeny,
		},
	}
}
