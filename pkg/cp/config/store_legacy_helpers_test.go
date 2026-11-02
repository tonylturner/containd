// SPDX-License-Identifier: Apache-2.0
package config

import (
	"encoding/json"
	"testing"
)

// Helpers for fixtures written in the previous storage formats.
func cloneConfigForPersist(cfg *Config) *Config {
	if cfg == nil {
		return nil
	}
	cp := *cfg
	if cfg.IDS.Rules != nil {
		cp.IDS.Rules = append([]IDSRule(nil), cfg.IDS.Rules...)
	}
	return &cp
}

func marshalStoredConfig(key string, cfg *Config) ([]byte, error) {
	stored := storedConfig{Config: *cfg}
	if key == configKeyCandidate || key == configKeyPrevious {
		stored.SnapshotFormat = snapshotFormatEmbeddedBank
	}
	return json.Marshal(stored)
}

// markLegacyIdentity models a database from before identity metadata existed.
func markLegacyIdentity(t *testing.T, s *SQLiteStore) {
	t.Helper()
	if _, err := s.db.Exec(`DELETE FROM running_identity_genesis`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM running_identity`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM runtime_transition`); err != nil {
		t.Fatal(err)
	}
}
