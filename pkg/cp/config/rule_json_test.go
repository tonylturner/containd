// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRuleJSONKeysMatchRuleJSONTags(t *testing.T) {
	ruleType := reflect.TypeOf(Rule{})
	tagNames := make([]string, 0, ruleType.NumField())
	for i := 0; i < ruleType.NumField(); i++ {
		field := ruleType.Field(i)
		tag, ok := field.Tag.Lookup("json")
		if !ok {
			t.Fatalf("Rule.%s has no JSON tag", field.Name)
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if name == "" {
			t.Fatalf("Rule.%s has an empty JSON tag name", field.Name)
		}
		tagNames = append(tagNames, name)
	}
	if !reflect.DeepEqual(ruleJSONKeys, tagNames) {
		t.Fatalf("ruleJSONKeys = %v, want Rule JSON tag names %v", ruleJSONKeys, tagNames)
	}
}

func TestRuleUnmarshalJSONRejectsUnknownAndDuplicateKeys(t *testing.T) {
	for _, input := range []string{
		`{"id":"rd-rule","state":["on"]}`,
		`{"id":"rd-rule","ID":"other"}`,
		`{"id":"rd-rule","action":"ALLOW","action":"DENY"}`,
	} {
		t.Run(input, func(t *testing.T) {
			var rule Rule
			err := json.Unmarshal([]byte(input), &rule)
			if err == nil || !strings.Contains(err.Error(), `id "rd-rule"`) {
				t.Fatalf("Unmarshal error = %v, want rule ID in error", err)
			}
			if strings.Contains(input, `"state"`) && !strings.Contains(err.Error(), `unknown key "state"`) {
				t.Fatalf("Unmarshal error = %v, want unknown-key error", err)
			}
			if strings.Contains(input, `"ID"`) && !strings.Contains(err.Error(), `unknown key "ID"`) {
				t.Fatalf("Unmarshal error = %v, want case-sensitive unknown-key error", err)
			}
			if strings.Contains(input, `"action":"ALLOW","action"`) && !strings.Contains(err.Error(), `duplicate key "action"`) {
				t.Fatalf("Unmarshal error = %v, want duplicate-key error", err)
			}
		})
	}
}

func TestRuleUnmarshalJSONAcceptsPersistedRuleKeys(t *testing.T) {
	const persisted = `{
		"schema_version":"0.1.6",
		"firewall":{"defaultAction":"DENY","rules":[{
			"id":"legacy",
			"description":"persisted rule",
			"sourceZones":["lan"],
			"destZones":["ot"],
			"sources":["192.0.2.0/24"],
			"destinations":["198.51.100.0/24"],
			"protocols":[{"name":"tcp","port":"2404"}],
			"identities":["operator"],
			"ics":{"protocol":"modbus","functionCode":[3],"unitId":1,"addresses":["0-10"],"readOnly":true,"writeOnly":false,"direction":"request","mode":"learn"},
			"schedule":{"daysOfWeek":["Monday"],"startTime":"08:00","endTime":"17:00","timezone":"UTC"},
			"action":"ALLOW",
			"log":true
		}]}
	}`

	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if _, err := store.db.ExecContext(context.Background(),
		`INSERT INTO configs (key, data, updated_at) VALUES (?, ?, ?)`,
		configKeyRunning, persisted, 1); err != nil {
		t.Fatalf("seed persisted config: %v", err)
	}
	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("load persisted config: %v", err)
	}
	if len(loaded.Firewall.Rules) != 1 || loaded.Firewall.Rules[0].ID != "legacy" {
		t.Fatalf("loaded rules = %+v, want legacy rule", loaded.Firewall.Rules)
	}
}

func TestRuleUnmarshalJSONNull(t *testing.T) {
	rule := Rule{ID: "preserved"}
	if err := json.Unmarshal([]byte("null"), &rule); err != nil {
		t.Fatalf("Unmarshal null: %v", err)
	}
	if rule.ID != "preserved" {
		t.Fatalf("rule after null = %+v, want unchanged", rule)
	}
}

func TestRateLimitJSONKeysMatchJSONTags(t *testing.T) {
	typ := reflect.TypeOf(RateLimitConfig{})
	var names []string
	for i := 0; i < typ.NumField(); i++ {
		name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		names = append(names, name)
	}
	if !reflect.DeepEqual(rateLimitJSONKeys, names) {
		t.Fatalf("rateLimitJSONKeys = %v, want %v", rateLimitJSONKeys, names)
	}
}

// rateLimit decodes strictly, like the rule around it; null clears it.
func TestRateLimitUnmarshalJSONIsStrict(t *testing.T) {
	for input, want := range map[string]string{
		`{"id":"r","action":"RATE_LIMIT","rateLimit":{"packetsPerSecond":10,"brust":5}}`:             `rule (id "r"): rateLimit: unknown key "brust"`,
		`{"id":"r","action":"RATE_LIMIT","rateLimit":{"packetsPerSecond":10,"packetsPerSecond":20}}`: `rule (id "r"): rateLimit: duplicate key "packetsPerSecond"`,
		`{"id":"r","action":"RATE_LIMIT","rateLimit":[10]}`:                                          `rule (id "r"): rateLimit: expected a JSON object`,
		`{"id":"r","action":"RATE_LIMIT","rateLimit":{"packetsPerSecond":-1}}`:                       `rule (id "r"): rateLimit: json: cannot unmarshal`,
	} {
		var r Rule
		if err := json.Unmarshal([]byte(input), &r); err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("%s: err = %v, want prefix %q", input, err, want)
		}
	}
	var r Rule
	if err := json.Unmarshal([]byte(`{"id":"r","action":"RATE_LIMIT","rateLimit":{"packetsPerSecond":10,"burst":5}}`), &r); err != nil ||
		!reflect.DeepEqual(r.RateLimit, &RateLimitConfig{PacketsPerSecond: 10, Burst: 5}) {
		t.Fatalf("valid rateLimit = %+v, %v", r.RateLimit, err)
	}
	if err := json.Unmarshal([]byte(`{"id":"r","action":"DENY","rateLimit":null}`), &r); err != nil || r.RateLimit != nil {
		t.Fatalf("null rateLimit = %+v, %v", r.RateLimit, err)
	}
}
