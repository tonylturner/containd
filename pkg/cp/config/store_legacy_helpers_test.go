// SPDX-License-Identifier: Apache-2.0
package config

import "encoding/json"

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
