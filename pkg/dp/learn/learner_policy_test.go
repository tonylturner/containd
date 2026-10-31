// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func loadRangerDangerPolicy(t *testing.T, name string) config.Config {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "cp", "config", "testdata", "rangerdanger", name))
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return cfg
}

// Learned rules inherit each policy's global mode: they stage into a policy
// without an inline path as learn, and enforce where the policy enforces.
func TestLearnedRulesLoadIntoRangerDangerPolicies(t *testing.T) {
	l := New()
	l.RecordEvent("10.40.40.10", "10.40.40.20", dpi.Event{
		Proto: "modbus", Kind: "request", Timestamp: time.Now().UTC(),
		Attributes: map[string]any{"function_code": uint8(3), "unit_id": uint8(1), "address": uint16(40001), "quantity": uint16(1), "is_write": false},
	})
	learned := l.GenerateRules()
	if len(learned) != 1 || learned[0].ICS.Mode != "" {
		t.Fatalf("learned rules = %+v", learned)
	}
	for name, wantMode := range map[string]string{"substation-weak.json": "monitor", "substation-improved.json": "enforce"} {
		t.Run(name, func(t *testing.T) {
			cfg := loadRangerDangerPolicy(t, name)
			cfg.Firewall.Rules = append(cfg.Firewall.Rules, learned...)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("learned rules refused: %v", err)
			}
			if got := rules.EffectiveMode(learned[0].ICS.Mode, cfg.DataPlane.DPIMode); got != wantMode {
				t.Fatalf("effective mode = %q, want %q", got, wantMode)
			}
		})
	}
	// Negative control: an explicit enforce mode is refused without a queue.
	cfg := loadRangerDangerPolicy(t, "substation-weak.json")
	explicit := learned[0]
	explicit.ICS.Mode = "enforce"
	cfg.Firewall.Rules = append(cfg.Firewall.Rules, explicit)
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "inline path") {
		t.Fatalf("explicit enforce without a queue accepted: %v", err)
	}
}
