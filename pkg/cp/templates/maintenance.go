// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package templates

import "github.com/tonylturner/containd/pkg/cp/config"

func init() {
	register(Template{
		Name:        "maintenance-window",
		Description: "Maintenance window – allows engineering workstations (L3) to access L1/L0 during scheduled maintenance",
		Rules:       maintenanceRules(),
	})
}

func maintenanceRules() []config.Rule {
	return []config.Rule{
		// During the maintenance window, allow Operations (L3) engineering
		// workstations to reach Basic Control (L1) for configuration,
		// firmware updates, and diagnostics.
		{
			ID:          "maint-l3-to-l1",
			Description: "Maintenance: allow Operations (L3) to Basic Control (L1) during window",
			SourceZones: []string{ZoneL3},
			DestZones:   []string{ZoneL1},
			Action:      config.ActionAllow,
			Schedule: &config.ScheduleConfig{
				DaysOfWeek: []string{"Saturday", "Sunday"},
				StartTime:  "02:00",
				EndTime:    "06:00",
				Timezone:   "America/New_York",
			},
		},
		// During the maintenance window, allow Operations (L3) engineering
		// workstations to reach Process (L0) devices directly for
		// calibration and commissioning.
		{
			ID:          "maint-l3-to-l0",
			Description: "Maintenance: allow Operations (L3) to Process (L0) during window",
			SourceZones: []string{ZoneL3},
			DestZones:   []string{ZoneL0},
			Action:      config.ActionAllow,
			Schedule: &config.ScheduleConfig{
				DaysOfWeek: []string{"Saturday", "Sunday"},
				StartTime:  "02:00",
				EndTime:    "06:00",
				Timezone:   "America/New_York",
			},
		},
		// Allow broader diagnostic protocols (ICMP) from L3 to L2 during
		// the maintenance window for network troubleshooting.
		{
			ID:          "maint-l3-to-l2-diag",
			Description: "Maintenance: allow Operations (L3) ICMP to Supervisory (L2) during window",
			SourceZones: []string{ZoneL3},
			DestZones:   []string{ZoneL2},
			Protocols:   []config.Protocol{{Name: "icmp"}},
			Action:      config.ActionAllow,
			Schedule: &config.ScheduleConfig{
				DaysOfWeek: []string{"Saturday", "Sunday"},
				StartTime:  "02:00",
				EndTime:    "06:00",
				Timezone:   "America/New_York",
			},
		},
	}
}
