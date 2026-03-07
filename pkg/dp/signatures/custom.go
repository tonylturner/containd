// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package signatures

import (
	"encoding/json"
	"fmt"
	"io"
)

// LoadFromJSON loads custom signatures from a JSON reader.
// The expected format is a JSON array of Signature objects:
//
//	[{"id": "CUSTOM-001", "name": "...", "protocol": "modbus", "severity": "high",
//	  "conditions": [{"field": "function_code", "op": "in", "value": [5,6,15,16]}]}]
func (e *Engine) LoadFromJSON(r io.Reader) error {
	var sigs []Signature
	if err := json.NewDecoder(r).Decode(&sigs); err != nil {
		return fmt.Errorf("signatures: invalid JSON: %w", err)
	}
	for _, sig := range sigs {
		if sig.ID == "" {
			return fmt.Errorf("signatures: signature missing required ID field")
		}
		if len(sig.Conditions) == 0 {
			return fmt.Errorf("signatures: signature %q has no conditions", sig.ID)
		}
		e.Add(sig)
	}
	return nil
}
