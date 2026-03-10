// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
	"gopkg.in/yaml.v3"
)

// SigmaRule is a minimal Sigma-like rule structure sufficient for conversion.
// It intentionally supports only a common subset of Sigma v1 fields.
type SigmaRule struct {
	Title       string                 `yaml:"title"`
	ID          string                 `yaml:"id"`
	Description string                 `yaml:"description"`
	Level       string                 `yaml:"level"`
	Tags        []string               `yaml:"tags"`
	LogSource   map[string]any         `yaml:"logsource"`
	Detection   map[string]any         `yaml:"detection"`
	Fields      []string               `yaml:"fields"`
	Status      string                 `yaml:"status"`
	References  []string               `yaml:"references"`
	FalsePos    []string               `yaml:"falsepositives"`
	Custom      map[string]any         `yaml:",inline"`
}

// ConvertSigmaYAML reads a Sigma YAML rule (single document) and returns a containd IDSRule.
func ConvertSigmaYAML(in []byte) (config.IDSRule, error) {
	var sr SigmaRule
	if err := yaml.Unmarshal(in, &sr); err != nil {
		return config.IDSRule{}, err
	}
	return ConvertSigmaRule(sr)
}

// ConvertSigmaFile parses raw Sigma YAML data (which may contain multiple
// documents separated by "---") and returns a slice of containd IDSRules.
func ConvertSigmaFile(data []byte) ([]config.IDSRule, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var rules []config.IDSRule
	for {
		var sr SigmaRule
		err := dec.Decode(&sr)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		r, err := ConvertSigmaRule(sr)
		if err != nil {
			return nil, err
		}
		r.SourceFormat = "sigma"
		r.RawSource = "" // multi-doc: cannot preserve per-rule raw source easily
		rules = append(rules, r)
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no Sigma rules found in data")
	}
	return rules, nil
}

// ConvertSigmaRule converts a parsed SigmaRule to a containd IDSRule.
func ConvertSigmaRule(sr SigmaRule) (config.IDSRule, error) {
	if sr.ID == "" && sr.Title == "" {
		return config.IDSRule{}, fmt.Errorf("sigma rule must have id or title")
	}
	conds, err := buildDetectionConditions(sr.Detection)
	if err != nil {
		return config.IDSRule{}, err
	}

	proto, kind := inferProtoKindFromTags(sr.Tags)
	rule := config.IDSRule{
		ID:           firstNonEmpty(sr.ID, slugify(sr.Title)),
		Title:        sr.Title,
		Description:  sr.Description,
		Proto:        proto,
		Kind:         kind,
		When:         conds,
		Severity:     mapSigmaLevel(sr.Level),
		Message:      sr.Title,
		Labels:       map[string]string{},
		SourceFormat: "sigma",
		References:   sr.References,
	}

	if len(sr.Tags) > 0 {
		rule.Labels["sigma.tags"] = strings.Join(sr.Tags, ",")
	}
	if sr.Status != "" {
		rule.Labels["sigma.status"] = sr.Status
	}
	if sr.LogSource != nil {
		if b, err := yaml.Marshal(sr.LogSource); err == nil {
			rule.Labels["sigma.logsource"] = strings.TrimSpace(string(b))
		}
	}
	if len(sr.References) > 0 {
		rule.Labels["sigma.references"] = strings.Join(sr.References, ",")
	}

	return rule, nil
}

// ConvertSigmaFiles converts one or more Sigma YAML files into containd IDS YAML bytes.
// The output schema is {version: 1, rules: [...] }.
func ConvertSigmaFiles(paths []string) ([]byte, error) {
	out := struct {
		Version int               `yaml:"version"`
		Rules   []config.IDSRule  `yaml:"rules"`
	}{Version: 1}

	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		r, err := ConvertSigmaYAML(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out.Rules = append(out.Rules, r)
	}

	sort.Slice(out.Rules, func(i, j int) bool { return out.Rules[i].ID < out.Rules[j].ID })
	return yaml.Marshal(out)
}

// WriteConvertedSigma writes converted IDS YAML to w.
func WriteConvertedSigma(w io.Writer, paths []string) error {
	b, err := ConvertSigmaFiles(paths)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, bytes.NewReader(b))
	return err
}

func inferProtoKindFromTags(tags []string) (string, string) {
	var proto, kind string
	for _, t := range tags {
		if strings.HasPrefix(t, "containd.proto.") {
			proto = strings.TrimPrefix(t, "containd.proto.")
		} else if strings.HasPrefix(t, "proto.") && proto == "" {
			proto = strings.TrimPrefix(t, "proto.")
		}
		if strings.HasPrefix(t, "containd.kind.") {
			kind = strings.TrimPrefix(t, "containd.kind.")
		} else if strings.HasPrefix(t, "kind.") && kind == "" {
			kind = strings.TrimPrefix(t, "kind.")
		}
	}
	return proto, kind
}

func mapSigmaLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "informational", "info", "low":
		return "low"
	case "medium", "moderate":
		return "medium"
	case "high":
		return "high"
	case "critical":
		return "critical"
	default:
		return ""
	}
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		if r == ' ' || r == '-' || r == '_' {
			return '-'
		}
		return -1
	}, s)
	s = strings.Trim(s, "-")
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return s
}

