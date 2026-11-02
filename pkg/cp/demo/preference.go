// SPDX-License-Identifier: Apache-2.0

// Package demo persists management's intent independently of engine runtime.
package demo

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type Preference string

const (
	Auto Preference = "auto"
	On   Preference = "on"
	Off  Preference = "off"
)

// Status deliberately excludes the engine's private run identifier.
type Status struct {
	Preference Preference `json:"preference"`
	Running    bool       `json:"running"`
	Loops      uint64     `json:"loops"`
	CaptureSet string     `json:"captureSet"`
	Capture    string     `json:"capture"`
	Error      string     `json:"error"`
	Reason     string     `json:"reason"`
}

// Load resolves an absent preference once. Corruption never enables demo.
func Load(path string) (Preference, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err = Save(path, Auto); err == nil {
			return Auto, nil
		}
	} else if err == nil {
		var record struct {
			Preference Preference `json:"preference"`
		}
		err = json.Unmarshal(data, &record)
		if err == nil && valid(record.Preference) {
			return record.Preference, nil
		}
		if err == nil {
			err = fmt.Errorf("invalid demo preference %q", record.Preference)
		}
	}
	return Off, fmt.Errorf("demo preference: %w", err)
}

func valid(p Preference) bool { return p == Auto || p == On || p == Off }

// Save atomically replaces demo.json using a private, synced temporary file.
// The containing config directory's existing permissions are left intact.
func Save(path string, p Preference) error {
	if !valid(p) {
		return fmt.Errorf("invalid demo preference %q", p)
	}
	data, err := json.Marshal(struct {
		Preference Preference `json:"preference"`
	}{p})
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".demo-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
