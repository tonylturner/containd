// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/limits"
)

func TestDataPlaneLimitsEffectiveAndStorage(t *testing.T) {
	var dp DataPlaneConfig
	if err := json.Unmarshal([]byte(`{"limits":{"maxFlows":2048}}`), &dp); err != nil {
		t.Fatal(err)
	}
	got := dp.Limits.Effective()
	want := limits.Default()
	want.MaxFlows = 2048
	if got != want {
		t.Fatalf("effective %+v", got)
	}
	raw, err := json.Marshal(dp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "maxTopTalkers") || strings.Contains(string(raw), "maxInspectionBytes") {
		t.Fatalf("rewrote defaults: %s", raw)
	}
	raw, err = json.Marshal(DataPlaneConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "limits") {
		t.Fatalf("omission: %s", raw)
	}
	if err := ValidateDataPlaneConfig(DataPlaneConfig{}); err != nil {
		t.Fatal(err)
	}
}
func TestDataPlaneLimitsValidation(t *testing.T) {
	for _, tc := range []struct {
		field, bounds string
		value         DataPlaneLimits
	}{
		{"maxFlows", "1024 and 262144", DataPlaneLimits{MaxFlows: -1}},
		{"maxFlows", "1024 and 262144", DataPlaneLimits{MaxFlows: 1023}},
		{"maxFlows", "1024 and 262144", DataPlaneLimits{MaxFlows: 262145}},
		{"maxTopTalkers", "64 and 262144", DataPlaneLimits{MaxTopTalkers: -1}},
		{"maxTopTalkers", "64 and 262144", DataPlaneLimits{MaxTopTalkers: 63}},
		{"maxTopTalkers", "64 and 262144", DataPlaneLimits{MaxTopTalkers: 262145}},
		{"maxInspectionBytes", "8388608 and 1073741824", DataPlaneLimits{MaxInspectionBytes: -1}},
		{"maxInspectionBytes", "8388608 and 1073741824", DataPlaneLimits{MaxInspectionBytes: 8388607}},
		{"maxInspectionBytes", "8388608 and 1073741824", DataPlaneLimits{MaxInspectionBytes: 1073741825}},
	} {
		dp := DataPlaneConfig{Limits: tc.value}
		cfg := DefaultConfig()
		cfg.DataPlane = dp
		for _, err := range []error{ValidateDataPlaneConfig(dp), cfg.Validate()} {
			if err == nil || !strings.Contains(err.Error(), tc.field) || !strings.Contains(err.Error(), tc.bounds) {
				t.Fatalf("%s: %v", tc.field, err)
			}
		}
	}
	for _, l := range []DataPlaneLimits{{MaxFlows: 1024, MaxTopTalkers: 64, MaxInspectionBytes: 8388608}, {MaxFlows: 262144, MaxTopTalkers: 262144, MaxInspectionBytes: 1073741824}} {
		if err := ValidateDataPlaneConfig(DataPlaneConfig{Limits: l}); err != nil {
			t.Fatal(err)
		}
	}
}
