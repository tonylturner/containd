// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestDesiredSelectionKeepsOriginalRequirements(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{{Name: "lan", Zone: "lan"}}
	if desiredSelection(cfg, rules.Snapshot{}).Forwarding {
		t.Fatal("single zone requires forwarding")
	}
	cfg.Interfaces = append(cfg.Interfaces, config.Interface{Name: "wan", Zone: "wan"})
	cfg.Services.AV.Enabled = true
	cfg.Services.AV.Mode = "clamav"
	cfg.Services.AV.ClamAV.FreshclamEnabled = true
	got := desiredSelection(cfg, rules.Snapshot{})
	if !got.Forwarding || !got.Trust {
		t.Fatalf("desired requirements lost: %+v", got)
	}
	cfg.Services.AV.Mode = "icap"
	if desiredSelection(cfg, rules.Snapshot{}).Trust {
		t.Fatal("inactive clamav settings require trust")
	}
}
