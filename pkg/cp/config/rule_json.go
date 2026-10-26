// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"encoding/json"
	"fmt"
)

var ruleJSONKeys = []string{
	"id", "description", "sourceZones", "destZones", "sources",
	"destinations", "protocols", "identities", "ics", "schedule",
	"action", "rateLimit", "tag", "log",
}

// UnmarshalJSON rejects unknown and duplicate rule keys instead of silently
// discarding them. The rule ID is included in errors when it can be decoded.
func (r *Rule) UnmarshalJSON(data []byte) error {
	if isJSONNull(data) {
		return nil
	}

	id := ruleIDFromJSON(data)
	if _, err := decodeStrictObject(data, ruleJSONKeys); err != nil {
		return ruleJSONError(id, err)
	}

	type ruleAlias Rule
	var decoded ruleAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return ruleJSONError(id, err)
	}
	*r = Rule(decoded)
	return nil
}

func ruleIDFromJSON(data []byte) string {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return ""
	}
	var id string
	_ = json.Unmarshal(fields["id"], &id)
	return id
}

func ruleJSONError(id string, err error) error {
	if id != "" {
		return fmt.Errorf("rule (id %q): %w", id, err)
	}
	return fmt.Errorf("rule: %w", err)
}
