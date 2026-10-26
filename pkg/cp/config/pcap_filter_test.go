// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import "testing"

func TestParsePCAPPortRange(t *testing.T) {
	tests := []struct {
		name  string
		value string
		min   uint16
		max   uint16
		valid bool
	}{
		{name: "empty", value: "", valid: true},
		{name: "single", value: "2404", min: 2404, max: 2404, valid: true},
		{name: "range", value: "1000-2000", min: 1000, max: 2000, valid: true},
		{name: "trimmed", value: " 53 ", min: 53, max: 53, valid: true},
		{name: "zero", value: "0"},
		{name: "too large", value: "65536"},
		{name: "negative", value: "-1"},
		{name: "descending", value: "2000-1000"},
		{name: "missing end", value: "1000-"},
		{name: "extra delimiter", value: "1-2-3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMin, gotMax, err := ParsePCAPPortRange(tt.value)
			if (err == nil) != tt.valid {
				t.Fatalf("ParsePCAPPortRange(%q) error = %v, want valid=%v", tt.value, err, tt.valid)
			}
			if tt.valid && (gotMin != tt.min || gotMax != tt.max) {
				t.Fatalf("ParsePCAPPortRange(%q) = %d-%d, want %d-%d", tt.value, gotMin, gotMax, tt.min, tt.max)
			}
		})
	}
}

func TestValidatePCAPConfigAllowsZoneOnlyAndValidatesPort(t *testing.T) {
	cfg := PCAPConfig{Enabled: true, Zones: []string{"lan"}, Filter: PCAPFilter{Port: "2404"}}
	if err := ValidatePCAPConfig(cfg); err != nil {
		t.Fatalf("zone-only PCAP config: %v", err)
	}

	cfg.Filter.Proto = "icmp"
	if err := ValidatePCAPConfig(cfg); err == nil {
		t.Fatal("expected port with ICMP validation error")
	}

	cfg.Filter = PCAPFilter{Port: "65536"}
	if err := ValidatePCAPConfig(cfg); err == nil {
		t.Fatal("expected out-of-range port validation error")
	}

	if err := ValidatePCAPConfig(PCAPConfig{Enabled: true}); err == nil {
		t.Fatal("expected enabled config without interface or zone to be rejected")
	}
}
