// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package templates

import (
	"fmt"
	"sort"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// Template describes a reusable policy template that can be applied to a
// configuration's firewall rules.
type Template struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Rules       []config.Rule `json:"rules"`
}

// registry is the global set of built-in templates, keyed by name.
var registry = map[string]Template{}

// register adds a template to the global registry. It is intended to be
// called from init() functions in sibling files.
func register(t Template) {
	registry[t.Name] = t
}

// List returns all available templates sorted by name.
func List() []Template {
	out := make([]Template, 0, len(registry))
	for _, t := range registry {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns a template by name, or an error if it does not exist.
func Get(name string) (*Template, error) {
	t, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("template %q not found", name)
	}
	return &t, nil
}

// Apply merges the rules from the named template into cfg's firewall rules.
// Existing rules are preserved; template rules are appended. Duplicate rule
// IDs (by exact string match) are skipped to allow safe re-application.
func Apply(name string, cfg *config.Config) error {
	t, err := Get(name)
	if err != nil {
		return err
	}
	existing := map[string]struct{}{}
	for _, r := range cfg.Firewall.Rules {
		existing[r.ID] = struct{}{}
	}
	for _, r := range t.Rules {
		if _, dup := existing[r.ID]; dup {
			continue
		}
		cfg.Firewall.Rules = append(cfg.Firewall.Rules, r)
		existing[r.ID] = struct{}{}
	}
	return nil
}
