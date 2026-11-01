// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// RequestConfigMode distinguishes full-document writes from backup imports.
type RequestConfigMode uint8

const (
	RequestConfigWrite RequestConfigMode = iota
	RequestConfigImport
)

// requestConfigKeys follows the public Config tags, excluding private migration
// evidence. Storage-only snapshot metadata deliberately is not a request key.
var requestConfigKeys = func() []string {
	typ := reflect.TypeFor[Config]()
	var keys []string
	for i := range typ.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		key, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if key != "" && key != "-" {
			keys = append(keys, key)
		}
	}
	return keys
}()

// DecodeRequestConfig accepts exact, unique root keys without changing nested
// compatibility or the decoding of stored snapshots. Only imports may discard
// the retired export section from schemas 0.1.0 through 0.1.7.
func DecodeRequestConfig(body []byte, mode RequestConfigMode) (*Config, error) {
	known := append([]string(nil), requestConfigKeys...)
	if mode == RequestConfigImport {
		known = append(known, "export")
	}
	fields, err := decodeStrictObject(body, known)
	if err != nil {
		var keyErr *objectKeyError
		if errors.As(err, &keyErr) {
			if keyErr.kind == "unknown" {
				return nil, unknownRequestKey(keyErr.key)
			}
			return nil, fmt.Errorf("duplicate top-level key %q", keyErr.key)
		}
		return nil, err
	}
	var cfg Config
	// Unmarshal the complete body as well: this rejects trailing JSON and keeps
	// the established nested decoders. The retired export value is not retained.
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, err
	}
	if _, present := fields["export"]; present {
		if _, hasSchema := fields["schema_version"]; hasSchema && !legacyExportSchema(cfg.SchemaVersion) {
			return nil, unknownRequestKey("export")
		}
	}
	return &cfg, nil
}

func unknownRequestKey(key string) error {
	for _, canonical := range requestConfigKeys {
		if strings.EqualFold(key, canonical) {
			return fmt.Errorf("unknown top-level key %q (did you mean %q?)", key, canonical)
		}
	}
	return fmt.Errorf("unknown top-level key %q", key)
}

func legacyExportSchema(schema string) bool {
	v, err := parseSemver(schema)
	return err == nil && v.major == 0 && v.minor == 1 && v.patch >= 0 && v.patch <= 7
}
