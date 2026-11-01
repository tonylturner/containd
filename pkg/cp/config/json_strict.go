// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

type objectKeyError struct {
	kind string
	key  string
}

func (e *objectKeyError) Error() string {
	return fmt.Sprintf("%s key %q", e.kind, e.key)
}

// decodeStrictObject splits one JSON object into its raw member values.
// Keys must appear in known (exact spelling) and at most once. Custom
// UnmarshalJSON methods use it because an outer DisallowUnknownFields does
// not reach them.
func decodeStrictObject(data []byte, known []string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, errors.New("expected a JSON object")
	}
	fields := make(map[string]json.RawMessage)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("expected an object key")
		}
		if !slices.Contains(known, key) {
			return nil, &objectKeyError{kind: "unknown", key: key}
		}
		if _, dup := fields[key]; dup {
			return nil, &objectKeyError{kind: "duplicate", key: key}
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		fields[key] = raw
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return fields, nil
}

func isJSONNull(raw []byte) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}
