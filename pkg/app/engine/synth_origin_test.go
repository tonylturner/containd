// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"testing"

	"github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/dp/engine"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestSynthIDSAlertsKeepDemoOrigin(t *testing.T) {
	store := dpevents.NewStore(8)
	dpEngine, err := engine.New(engine.Config{Events: store})
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}
	defer dpEngine.Close()

	dpEngine.LoadRules(rules.Snapshot{
		IDS: rules.IDSConfig{
			Enabled: true,
			Rules: []rules.IDSRule{{
				ID:    "write-alert",
				Proto: "modbus",
				When: rules.IDSCondition{
					Field: "attr.is_write",
					Op:    "equals",
					Value: true,
				},
			}},
		},
	})
	synthIDSCallback(dpEngine)(dpevents.Event{
		Origin:     telemetry.OriginDemo,
		FlowID:     "synthetic-flow",
		Proto:      "modbus",
		Kind:       "request",
		Attributes: map[string]any{"is_write": true},
	})

	got := store.List(0)
	if len(got) != 1 || got[0].Proto != "ids" || got[0].Kind != "alert" {
		t.Fatalf("synthetic IDS events = %+v", got)
	}
	if got[0].Origin != telemetry.OriginDemo {
		t.Fatalf("synthetic IDS alert origin = %q, want demo", got[0].Origin)
	}
}
