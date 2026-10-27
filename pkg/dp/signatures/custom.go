// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package signatures

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/tonylturner/containd/pkg/dp/ics"
)

// LoadFromJSON loads custom signatures from a JSON reader.
// The expected format is a JSON array of Signature objects:
//
//	[{"id": "CUSTOM-001", "name": "...", "protocol": "modbus", "severity": "high",
//	  "conditions": [{"field": "function_code", "op": "in", "value": [5,6,15,16]}],
//	  "threshold": {"count": 10, "windowSeconds": 60}}]
//
// threshold is optional. The whole array is validated before any signature
// is added.
func (e *Engine) LoadFromJSON(r io.Reader) error {
	var sigs []Signature
	if err := json.NewDecoder(r).Decode(&sigs); err != nil {
		return fmt.Errorf("signatures: invalid JSON: %w", err)
	}
	for _, sig := range sigs {
		if err := sig.Validate(); err != nil {
			return err
		}
	}
	for _, sig := range sigs {
		e.Add(sig)
	}
	return nil
}

// Validate checks the fields a signature needs to match.
func (s Signature) Validate() error {
	if err := ics.ValidateSignature(s.ID, s.Protocol); err != nil {
		return err
	}
	if s.ID == "" {
		return fmt.Errorf("signatures: signature missing required ID field")
	}
	if len(s.Conditions) == 0 {
		return fmt.Errorf("signatures: signature %q has no conditions", s.ID)
	}
	if s.Threshold != nil {
		if err := s.Threshold.validate(); err != nil {
			return fmt.Errorf("signatures: signature %q: %w", s.ID, err)
		}
	}
	return nil
}
