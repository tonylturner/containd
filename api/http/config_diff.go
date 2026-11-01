// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// Config reads are small editable documents. Exports/backups intentionally do
// not use this helper: they must include the complete deployed IDS bank.
func configReadCopy(cfg *config.Config) *config.Config {
	cp := cfg.RedactedCopy()
	if cp != nil {
		cp.IDS.Rules = nil
	}
	return cp
}

type idsBankSummary struct {
	Count  int    `json:"count"`
	SHA256 string `json:"sha256"`
}

func summarizeIDSBank(cfg *config.Config) (idsBankSummary, error) {
	rules := []config.IDSRule{}
	if cfg != nil && cfg.IDS.Rules != nil {
		rules = cfg.IDS.Rules
	}
	body, err := json.Marshal(rules)
	if err != nil {
		return idsBankSummary{}, err
	}
	return idsBankSummary{Count: len(rules), SHA256: fmt.Sprintf("%x", sha256.Sum256(body))}, nil
}

// Compare wire-level sections before redaction. Never return secret values or
// secret digests; only section names leave this comparison.
func changedConfigSections(running, candidate *config.Config, runningBank, candidateBank idsBankSummary) ([]string, error) {
	sections := make([]map[string]json.RawMessage, 2)
	for i, cfg := range []*config.Config{running, candidate} {
		// The bank was already hashed. Do not serialize it again with each
		// config, and do not redact until after comparing the other fields.
		if cfg != nil {
			cp := *cfg
			cp.IDS.Rules = nil
			cfg = &cp
		}
		body, err := json.Marshal(cfg)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(body, &sections[i]); err != nil {
			return nil, err
		}
	}
	keys := map[string]bool{}
	for _, section := range sections {
		for key := range section {
			keys[key] = true
		}
	}
	changed := []string{}
	for key := range keys {
		if !bytes.Equal(sections[0][key], sections[1][key]) || key == "ids" && runningBank != candidateBank {
			changed = append(changed, key)
		}
	}
	sort.Strings(changed)
	return changed, nil
}

func diffConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		snapshot, err := store.ReadSnapshot(c.Request.Context(), config.SnapshotPair, true)
		if err != nil {
			internalError(c, err)
			return
		}
		running, candidate := snapshot.Running, snapshot.Candidate
		configRevisionResponse(c, snapshot.Revision)
		runningBank, err := summarizeIDSBank(running)
		if err != nil {
			internalError(c, err)
			return
		}
		candidateBank, err := summarizeIDSBank(candidate)
		if err != nil {
			internalError(c, err)
			return
		}
		changed, err := changedConfigSections(running, candidate, runningBank, candidateBank)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"changed":         len(changed) != 0,
			"changedSections": changed,
			"running":         configReadCopy(running),
			"candidate":       configReadCopy(candidate),
			"idsBank": gin.H{
				"running": runningBank, "candidate": candidateBank,
			},
		})
	}
}
