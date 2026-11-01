// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

// Repair applies a boot repair independently to running and an existing
// candidate in one transaction. It never seeds a candidate or changes previous
// or pending state. The callback must not call Store or mutate external state.
// Repair requires SQLite persistence; it is intentionally not part of the
// general Store interface used by API/CLI consumers. Reservation validation is
// deliberately deferred until after normalization: legacy NIC bindings and
// residual conflicts must not prevent management from serving recovery.
func Repair(ctx context.Context, store Store, edit func(*Config) error) (*Config, error) {
	s, ok := store.(*SQLiteStore)
	if !ok {
		return nil, errors.New("boot repair requires a SQLite config store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.beginConfigTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	running, err := loadRunningFrom(ctx, tx)
	if err != nil {
		return nil, err
	}
	candidate, err := loadKindFrom(ctx, tx, configKeyCandidate)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	before := make(map[*Config][]byte)
	for _, cfg := range []*Config{running, candidate} {
		if cfg != nil {
			before[cfg], err = json.Marshal(cfg)
			if err != nil {
				return nil, err
			}
		}
	}
	// Only transaction writes happen after both repairs and validations succeed.
	for _, cfg := range []*Config{running, candidate} {
		if cfg == nil {
			continue
		}
		if err := edit(cfg); err != nil {
			return nil, err
		}
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("repaired config validation failed: %w", err)
		}
	}
	changed := false
	for _, item := range []struct {
		key string
		cfg *Config
	}{{configKeyRunning, running}, {configKeyCandidate, candidate}} {
		if item.cfg == nil {
			continue
		}
		after, err := json.Marshal(item.cfg)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(before[item.cfg], after) {
			continue
		}
		changed = true
		if item.key == configKeyRunning {
			if err := replaceChangedIDSRulesTx(ctx, tx, item.cfg.IDS.Rules); err != nil {
				return nil, err
			}
		}
		if err := writeConfigTx(ctx, tx, item.key, item.cfg); err != nil {
			return nil, err
		}
	}
	if changed {
		if _, err := s.commitRevisionTx(ctx, tx); err != nil {
			return nil, err
		}
	}
	return running, nil
}

// A loaded config often carries an unchanged bank. Do not delete/reinsert it
// on Save or boot repair; bank order is not significant (the table is keyed).
func replaceChangedIDSRulesTx(ctx context.Context, tx *sql.Tx, rules []IDSRule) error {
	current, err := loadIDSRulesFrom(ctx, tx)
	if err != nil {
		return err
	}
	if len(current) == len(rules) {
		byID := make(map[string]IDSRule, len(rules))
		for _, rule := range rules {
			byID[rule.ID] = rule
		}
		equal := true
		for _, rule := range current {
			other, ok := byID[rule.ID]
			if !ok || !reflect.DeepEqual(rule, other) {
				equal = false
				break
			}
		}
		if equal {
			return nil
		}
	}
	return replaceIDSRulesTx(ctx, tx, rules)
}
