// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/ics"
)

func TestParsingDefaultsNeedNoMigration(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SchemaVersion = "0.1.7"
	if err := UpgradeInPlace(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.SchemaVersion != SchemaVersionCurrent || cfg.DataPlane.DPIICSParsing != nil {
		t.Fatalf("upgrade materialized parsing defaults: %+v", cfg.DataPlane)
	}
	for _, name := range []string{"modbus", "dnp3", "cip", "iec104"} {
		if got := ics.EffectiveParsing(cfg.DataPlane.DPIICSParsing, name); got != ics.Tolerant {
			t.Fatalf("%s default: %s", name, got)
		}
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "dpiIcsParsing") {
		t.Fatal("serialization materialized parsing defaults")
	}
}

func TestDataPlaneParsingValidation(t *testing.T) {
	for _, modes := range []map[string]string{
		nil, {}, {"modbus": ""}, {"dnp3": "tolerant"},
		{"modbus": "strict", "dnp3": "strict", "cip": "strict", "iec104": "strict"},
		{"modbus": "invalid"}, {"enip": "strict"}, {"unknown": "tolerant"},
	} {
		cfg := DefaultConfig()
		cfg.DataPlane.DPIICSParsing = modes
		wantErr := ics.ValidateParsing(modes) != nil
		for _, err := range []error{ValidateDataPlaneConfig(cfg.DataPlane), cfg.Validate()} {
			if (err != nil) != wantErr {
				t.Fatalf("parsing %v: err=%v wantErr=%v", modes, err, wantErr)
			}
		}
	}
}
