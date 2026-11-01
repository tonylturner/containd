// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// iec104Config returns a config whose dataplane can activate an IEC104
// enforce envelope, with the given rules.
func iec104Config(rules ...Rule) *Config {
	return &Config{SchemaVersion: SchemaVersionCurrent,
		System: SystemConfig{Hostname: "containd"},
		Zones:  []Zone{{Name: "lan4"}, {Name: "lan1"}},
		DataPlane: DataPlaneConfig{
			DPIEnabled:      true,
			DPIMode:         "enforce",
			NFQueueGroup:    101,
			DPIICSProtocols: map[string]bool{"modbus": true, "iec104": true},
		},
		Firewall: FirewallConfig{DefaultAction: ActionDeny, Rules: rules},
	}
}

func iecRule(id string, action Action, ics ICSPredicate) Rule {
	ics.Protocol = ICSProtocolIEC104
	return Rule{
		ID:           id,
		SourceZones:  []string{"lan4"},
		DestZones:    []string{"lan1"},
		Sources:      []string{"10.60.60.10/32"},
		Destinations: []string{"10.30.30.30/32"},
		Protocols:    []Protocol{{Name: "tcp", Port: "2404"}},
		ICS:          ics,
		Action:       action,
	}
}

func wantValidateError(t *testing.T, cfg *Config, want string) {
	t.Helper()
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Validate err = %v, want it to contain %q", err, want)
	}
}

func TestValidateIEC104PredicateRanges(t *testing.T) {
	cases := []struct {
		name string
		ics  ICSPredicate
		want string
	}{
		{"typeId 0", ICSPredicate{TypeIDs: []int{0}}, "typeIds value 0 out of range"},
		{"typeId 256", ICSPredicate{TypeIDs: []int{256}}, "typeIds value 256 out of range"},
		{"class", ICSPredicate{Classes: []string{"command"}}, `classes value "command" invalid`},
		{"broadcast ca", ICSPredicate{CA: []uint16{1, 65535}}, "ca 65535 is the broadcast address"},
		{"ioa above 24 bits", ICSPredicate{IOA: []IOARange{{Start: 0, End: 16777216}}}, "ioa end 16777216 out of range"},
		{"ioa start after end", ICSPredicate{IOA: []IOARange{{Start: 5, End: 4}}}, "start after end"},
		{"ioa overlap", ICSPredicate{IOA: []IOARange{{Start: 10, End: 20}, {Start: 1, End: 10}}}, "ranges 1-10 and 10-20 overlap"},
		{"ioa duplicate", ICSPredicate{IOA: []IOARange{{Start: 7, End: 7}, {Start: 7, End: 7}}}, "overlap"},
		{"programmatic empty typeIds", ICSPredicate{TypeIDs: []int{}}, "typeIds must not be empty"},
		{"programmatic empty classes", ICSPredicate{Classes: []string{}}, "classes must not be empty"},
		{"programmatic empty ca", ICSPredicate{CA: []uint16{}}, "ca must not be empty"},
		{"programmatic empty ioa", ICSPredicate{IOA: []IOARange{}}, "ioa must not be empty"},
		{"functionCode", ICSPredicate{FunctionCode: []uint8{}}, "functionCode is not supported for protocol iec104"},
		{"unitId", ICSPredicate{UnitID: new(uint8)}, "unitId is not supported"},
		{"addresses", ICSPredicate{Addresses: []string{"1"}}, "addresses is not supported"},
		{"objectClasses", ICSPredicate{ObjectClasses: []uint16{1}}, "objectClasses is not supported"},
		{"writeOnly", ICSPredicate{WriteOnly: true}, "writeOnly is not supported"},
		{"direction", ICSPredicate{Direction: "both"}, `direction invalid "both"`},
		{"mode", ICSPredicate{Mode: "block"}, `mode invalid "block"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantValidateError(t, iec104Config(iecRule("r", ActionDeny, tc.ics)), tc.want)
		})
	}

	ok := iec104Config(iecRule("r", ActionAllow, ICSPredicate{
		TypeIDs: []int{1, 3, 5, 7, 9, 11, 13, 15, 21, 30, 31, 32, 33, 34, 35, 36, 37, 46},
		Classes: []string{"monitor", "control"},
		CA:      []uint16{0, 65534},
		IOA:     []IOARange{{Start: 0, End: 0}, {Start: 65536, End: 65567}, {Start: 16777215, End: 16777215}},
	}))
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid IEC104 rule rejected: %v", err)
	}
}

func TestValidateICSPredicateProtocolRules(t *testing.T) {
	cases := []struct {
		name string
		ics  ICSPredicate
		want string
	}{
		{"functionCode without protocol", ICSPredicate{FunctionCode: []uint8{3}}, "functionCode needs an ics protocol"},
		{"readOnly without protocol", ICSPredicate{ReadOnly: true}, "readOnly needs an ics protocol"},
		{"direction without protocol", ICSPredicate{Direction: "request"}, "direction needs an ics protocol"},
		{"typeIds without protocol", ICSPredicate{TypeIDs: []int{46}}, "typeIds needs an ics protocol"},
		{"invalid mode without protocol", ICSPredicate{Mode: "on"}, `mode invalid "on"`},
		{"unknown protocol", ICSPredicate{Protocol: "iec61850"}, `protocol "iec61850" is not supported`},
		{"case variant protocol", ICSPredicate{Protocol: "Modbus"}, `protocol "Modbus" is not supported`},
		{"modbus with ca", ICSPredicate{Protocol: "modbus", CA: []uint16{1}}, "ca is only supported for protocol iec104"},
		{"objectClasses on modbus", ICSPredicate{Protocol: "modbus", ObjectClasses: []uint16{1}}, "objectClasses only supported for cip"},
		{"readOnly and writeOnly", ICSPredicate{Protocol: "modbus", ReadOnly: true, WriteOnly: true}, "both readOnly and writeOnly"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := iec104Config(Rule{ID: "r", ICS: tc.ics, Action: ActionAllow})
			wantValidateError(t, cfg, tc.want)
		})
	}

	// ics: {} is a pure L3/L4 rule. mode alone stays valid: the policy
	// templates put it on their L3/L4 rules.
	for _, ics := range []ICSPredicate{{}, {FunctionCode: []uint8{}}} {
		cfg := iec104Config(Rule{ID: "r", ICS: ics, Action: ActionAllow})
		if err := cfg.Validate(); err != nil {
			t.Fatalf("predicate %+v rejected: %v", ics, err)
		}
	}
}

func TestValidateIEC104AllowTypes(t *testing.T) {
	wantValidateError(t, iec104Config(iecRule("r", ActionAllow, ICSPredicate{TypeIDs: []int{46, 104}})),
		"typeIds value 104 has no IEC104 descriptor")
	wantValidateError(t, iec104Config(iecRule("r", ActionAllow, ICSPredicate{Classes: []string{"unknown"}})),
		`classes "unknown" cannot be allowed`)

	allowed := []*Config{
		iec104Config(iecRule("deny", ActionDeny, ICSPredicate{TypeIDs: []int{104, 200}, Classes: []string{"unknown"}})),
		iec104Config(iecRule("monitor", ActionAllow, ICSPredicate{TypeIDs: []int{104}, Mode: "monitor"})),
	}
	globalLearn := iec104Config(iecRule("global-learn", ActionAllow, ICSPredicate{TypeIDs: []int{106}}))
	globalLearn.DataPlane.DPIMode = "monitor"
	allowed = append(allowed, globalLearn)
	for _, cfg := range allowed {
		if err := cfg.Validate(); err != nil {
			t.Fatalf("rule %s rejected: %v", cfg.Firewall.Rules[0].ID, err)
		}
	}
}

func TestValidateIEC104EnforceStaticCauses(t *testing.T) {
	rule := iecRule("cc-rtu", ActionAllow, ICSPredicate{ReadOnly: true, Mode: "enforce"})
	cases := []struct {
		name   string
		mutate func(*DataPlaneConfig)
		want   string
	}{
		{"dpi off", func(dp *DataPlaneConfig) { dp.DPIEnabled = false }, "needs dataplane.dpiEnabled"},
		{"decoder off", func(dp *DataPlaneConfig) { dp.DPIICSProtocols["iec104"] = false }, "dpiIcsProtocols.iec104 is false"},
		{"queue 0 means AF_PACKET capture", func(dp *DataPlaneConfig) { dp.NFQueueGroup = 0 }, "needs NFQUEUE capture"},
		{"ip exclusion on the server", func(dp *DataPlaneConfig) {
			dp.DPIExclusions = []DPIExclusion{{Value: "10.30.30.30", Type: "ip"}}
		}, `dpi exclusion "10.30.30.30" overlaps`},
		{"cidr exclusion around the client", func(dp *DataPlaneConfig) {
			dp.DPIExclusions = []DPIExclusion{{Value: "10.60.0.0/16", Type: "cidr"}}
		}, `dpi exclusion "10.60.0.0/16" overlaps`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := iec104Config(rule)
			tc.mutate(&cfg.DataPlane)
			wantValidateError(t, cfg, tc.want)
		})
	}

	t.Run("any-address side overlaps every exclusion", func(t *testing.T) {
		open := rule
		open.Sources = nil
		cfg := iec104Config(open)
		cfg.DataPlane.DPIExclusions = []DPIExclusion{{Value: "192.0.2.1", Type: "ip"}}
		wantValidateError(t, cfg, "overlaps the iec104 enforce envelope")
	})

	t.Run("activatable", func(t *testing.T) {
		cfg := iec104Config(rule)
		cfg.DataPlane.DPIExclusions = []DPIExclusion{
			{Value: "192.0.2.1", Type: "ip"},
			{Value: "198.51.100.0/24", Type: "cidr"},
			{Value: "updates.example.com", Type: "domain"},
		}
		delete(cfg.DataPlane.DPIICSProtocols, "iec104") // absent = enabled
		if err := cfg.Validate(); err != nil {
			t.Fatalf("activatable enforce config rejected: %v", err)
		}
	})

	t.Run("learn envelope has no static requirements", func(t *testing.T) {
		learn := iecRule("cc-rtu", ActionAllow, ICSPredicate{ReadOnly: true, Mode: "monitor"})
		cfg := iec104Config(learn)
		cfg.DataPlane = DataPlaneConfig{DPIMode: "enforce"}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("learn IEC rule rejected: %v", err)
		}
	})

	t.Run("blank rule mode inherits global enforce", func(t *testing.T) {
		inherit := iecRule("cc-rtu", ActionAllow, ICSPredicate{ReadOnly: true})
		cfg := iec104Config(inherit)
		cfg.DataPlane.NFQueueGroup = 0
		wantValidateError(t, cfg, "needs NFQUEUE capture")
	})
}

// Commit, candidate and import all save through the store, which
// validates before it writes anything.
func TestStoreRejectsUnactivatableIEC104Enforce(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "cfg.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()

	cfg := iec104Config(iecRule("cc-rtu", ActionAllow, ICSPredicate{ReadOnly: true, Mode: "enforce"}))
	cfg.DataPlane.DPIICSProtocols["iec104"] = false
	if err := testSaveCandidate(store, ctx, cfg); err == nil || !strings.Contains(err.Error(), "iec104") {
		t.Fatalf("SaveCandidate err = %v, want iec104 rejection", err)
	}
	if err := store.Save(ctx, cfg); err == nil || !strings.Contains(err.Error(), "iec104") {
		t.Fatalf("Save err = %v, want iec104 rejection", err)
	}
	if _, err := store.Load(ctx); err != ErrNotFound {
		t.Fatalf("Load after rejected save err = %v, want ErrNotFound", err)
	}
}

func TestSchemaVersion0110(t *testing.T) {
	if SchemaVersionCurrent != "0.1.10" {
		t.Fatalf("SchemaVersionCurrent = %s, want 0.1.10", SchemaVersionCurrent)
	}
	old := &Config{SchemaVersion: "0.1.0"}
	if err := UpgradeInPlace(old); err != nil || old.SchemaVersion != "0.1.10" {
		t.Fatalf("0.1.0 upgrade = %s, %v", old.SchemaVersion, err)
	}
	current, err := parseSemver(SchemaVersionCurrent)
	if err != nil {
		t.Fatal(err)
	}
	newer := &Config{SchemaVersion: fmt.Sprintf("%d.%d.%d", current.major, current.minor, current.patch+1)}
	if err := UpgradeInPlace(newer); err == nil {
		t.Fatal("future schema must be rejected as newer than supported")
	}
}

// Both shipped RangerDanger US policies still load under strict
// decoding, validate, and survive a marshal round trip unchanged. The weak
// policy has no semantic ICS rule; the improved one enforces Modbus and
// DNP3 rules through NFQUEUE, so it passes the inline-path requirement.
func TestRangerDangerUSPoliciesLoad(t *testing.T) {
	for name, wantEnforce := range map[string]bool{"substation-weak.json": false, "substation-improved.json": true} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "rangerdanger", name))
			if err != nil {
				t.Fatal(err)
			}
			var cfg Config
			if err := json.Unmarshal(raw, &cfg); err != nil {
				t.Fatalf("strict decode: %v", err)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}
			enforce := 0
			for _, r := range cfg.Firewall.Rules {
				if r.ICS.Protocol != "" && rules.EffectiveMode(r.ICS.Mode, cfg.DataPlane.DPIMode) == "enforce" {
					enforce++
				}
			}
			if (enforce > 0) != wantEnforce {
				t.Fatalf("semantic enforce rules = %d, want any: %v", enforce, wantEnforce)
			}
			body, err := json.Marshal(&cfg)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var again Config
			if err := json.Unmarshal(body, &again); err != nil {
				t.Fatalf("re-decode: %v", err)
			}
			if !reflect.DeepEqual(again.Firewall.Rules, cfg.Firewall.Rules) {
				t.Fatalf("rules changed in round trip:\n%+v\n%+v", cfg.Firewall.Rules, again.Firewall.Rules)
			}
		})
	}
}
