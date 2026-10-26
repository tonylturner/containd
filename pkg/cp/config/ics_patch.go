// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"encoding/json"
	"fmt"
)

// PatchICSPredicate applies the raw "ics" object of a rule PATCH to cur.
// The patch is decoded strictly, so its own unknown and duplicate keys are
// errors. A patch that changes the protocol replaces the predicate; any
// other patch overlays its keys on cur and the result is decoded strictly,
// so a merge cannot carry keys the protocol rejects. A JSON null clears
// the predicate.
func PatchICSPredicate(cur ICSPredicate, patch json.RawMessage) (ICSPredicate, error) {
	if isJSONNull(patch) {
		return ICSPredicate{}, nil
	}
	fields, err := decodeStrictObject(patch, icsPredicateKeys)
	if err != nil {
		return ICSPredicate{}, fmt.Errorf("ics: %w", err)
	}
	var out ICSPredicate
	if raw, ok := fields["protocol"]; ok {
		var protocol string
		if err := json.Unmarshal(raw, &protocol); err != nil {
			return ICSPredicate{}, fmt.Errorf("ics protocol: %w", err)
		}
		if protocol != cur.Protocol {
			err := json.Unmarshal(patch, &out)
			return out, err
		}
	}
	base, err := json.Marshal(cur)
	if err != nil {
		return ICSPredicate{}, err
	}
	merged, err := decodeStrictObject(base, icsPredicateKeys)
	if err != nil {
		return ICSPredicate{}, err
	}
	for key, raw := range fields {
		merged[key] = raw
	}
	body, err := json.Marshal(merged)
	if err != nil {
		return ICSPredicate{}, err
	}
	err = json.Unmarshal(body, &out)
	return out, err
}
