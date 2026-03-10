// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// ParseYARARule parses a single YARA rule text block and returns a containd IDSRule.
func ParseYARARule(text string) (config.IDSRule, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return config.IDSRule{}, fmt.Errorf("empty YARA rule")
	}

	name, tags, rest, err := parseYARARuleHeader(text)
	if err != nil {
		return config.IDSRule{}, err
	}

	meta := parseYARASection(rest, "meta")
	stringsSection := parseYARASection(rest, "strings")
	condition := parseYARASection(rest, "condition")

	metaMap := parseYARAMeta(meta)

	rule := config.IDSRule{
		ID:           "yara-" + slugify(name),
		Title:        name,
		Severity:     mapYARASeverity(metaMap["severity"]),
		Labels:       map[string]string{},
		SourceFormat: "yara",
		RawSource:    text,
		ConversionNotes: []string{
			"YARA rules match file/binary content and are not evaluated against network DPI events",
		},
	}

	if desc, ok := metaMap["description"]; ok {
		rule.Description = desc
	}
	if author, ok := metaMap["author"]; ok {
		rule.Labels["author"] = author
	}
	if ref, ok := metaMap["reference"]; ok {
		rule.References = append(rule.References, ref)
	}
	if refs, ok := metaMap["references"]; ok {
		for _, r := range strings.Split(refs, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				rule.References = append(rule.References, r)
			}
		}
	}
	if cve, ok := metaMap["cve"]; ok {
		rule.CVE = append(rule.CVE, strings.TrimSpace(cve))
	}
	if mitre, ok := metaMap["mitre_attack"]; ok {
		rule.MITREAttackIDs = append(rule.MITREAttackIDs, strings.TrimSpace(mitre))
	}

	if len(tags) > 0 {
		rule.Labels["yara.tags"] = strings.Join(tags, ",")
	}
	if condition != "" {
		rule.Labels["yara.condition"] = strings.TrimSpace(condition)
	}
	rule.Labels["evaluable"] = "false"

	// Store remaining meta fields.
	for k, v := range metaMap {
		switch k {
		case "description", "author", "severity", "reference", "references", "cve", "mitre_attack":
			continue
		default:
			rule.Labels["yara.meta."+k] = v
		}
	}

	rule.YARAStrings = parseYARAStrings(stringsSection)

	return rule, nil
}

// ConvertYARAFile parses a YARA .yar file (which may contain multiple rules,
// imports, and comments) and returns a slice of containd IDSRules.
func ConvertYARAFile(data []byte) ([]config.IDSRule, error) {
	text := stripYARAComments(string(data))
	blocks := splitYARARules(text)
	if len(blocks) == 0 {
		return nil, fmt.Errorf("no YARA rules found")
	}

	var rules []config.IDSRule
	for _, block := range blocks {
		r, err := ParseYARARule(block)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// ConvertYARAFiles reads one or more YARA files and returns sorted IDSRules.
func ConvertYARAFiles(paths []string) ([]config.IDSRule, error) {
	var all []config.IDSRule
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		rules, err := ConvertYARAFile(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		all = append(all, rules...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return all, nil
}

// parseYARARuleHeader extracts the rule name, tags, and body from "rule Name : tag1 tag2 { ... }".
func parseYARARuleHeader(text string) (name string, tags []string, body string, err error) {
	// Find "rule <name> [: <tags>] {"
	re := regexp.MustCompile(`(?s)^\s*(?:private\s+|global\s+)*rule\s+(\w+)\s*(?::\s*([^{]+))?\s*\{(.*)\}\s*$`)
	m := re.FindStringSubmatch(text)
	if m == nil {
		return "", nil, "", fmt.Errorf("invalid YARA rule header")
	}
	name = m[1]
	if m[2] != "" {
		for _, t := range strings.Fields(strings.TrimSpace(m[2])) {
			tags = append(tags, t)
		}
	}
	body = m[3]
	return name, tags, body, nil
}

// parseYARASection extracts the content of a named section (meta, strings, condition).
func parseYARASection(body, section string) string {
	lines := strings.Split(body, "\n")
	var sb strings.Builder
	inSection := false
	sectionHeader := regexp.MustCompile(`^\s*(meta|strings|condition)\s*:`)
	for _, line := range lines {
		if sectionHeader.MatchString(line) {
			m := sectionHeader.FindStringSubmatch(line)
			if m[1] == section {
				inSection = true
				// Include anything after the colon on the same line.
				idx := strings.Index(line, ":")
				rest := strings.TrimSpace(line[idx+1:])
				if rest != "" {
					sb.WriteString(rest)
					sb.WriteString("\n")
				}
				continue
			}
			if inSection {
				break
			}
			continue
		}
		if inSection {
			sb.WriteString(line)
			sb.WriteString("\n")
		}
	}
	return strings.TrimSpace(sb.String())
}

// parseYARAMeta parses meta key = "value" or key = number lines.
func parseYARAMeta(section string) map[string]string {
	m := map[string]string{}
	if section == "" {
		return m
	}
	re := regexp.MustCompile(`^\s*(\w+)\s*=\s*(.+)$`)
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		match := re.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		key := strings.ToLower(match[1])
		val := strings.TrimSpace(match[2])
		// Strip surrounding quotes.
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		m[key] = val
	}
	return m
}

// parseYARAStrings parses the strings section into YARAString structs.
func parseYARAStrings(section string) []config.YARAString {
	if section == "" {
		return nil
	}
	var out []config.YARAString
	// Match: $name = "text" [modifiers] | $name = { hex } | $name = /regex/ [modifiers]
	reText := regexp.MustCompile(`^\s*(\$\w+)\s*=\s*"((?:[^"\\]|\\.)*)"\s*(.*)$`)
	reHex := regexp.MustCompile(`^\s*(\$\w+)\s*=\s*\{([^}]*)\}\s*(.*)$`)
	reRegex := regexp.MustCompile(`^\s*(\$\w+)\s*=\s*/(.+)/\s*(.*)$`)

	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if m := reHex.FindStringSubmatch(line); m != nil {
			out = append(out, config.YARAString{
				Name:    m[1],
				Pattern: strings.TrimSpace(m[2]),
				Type:    "hex",
			})
			continue
		}

		if m := reRegex.FindStringSubmatch(line); m != nil {
			ys := config.YARAString{
				Name:    m[1],
				Pattern: m[2],
				Type:    "regex",
			}
			applyYARAModifiers(&ys, m[3])
			out = append(out, ys)
			continue
		}

		if m := reText.FindStringSubmatch(line); m != nil {
			ys := config.YARAString{
				Name:    m[1],
				Pattern: m[2],
				Type:    "text",
			}
			applyYARAModifiers(&ys, m[3])
			out = append(out, ys)
			continue
		}
	}
	return out
}

func applyYARAModifiers(ys *config.YARAString, mods string) {
	mods = strings.ToLower(strings.TrimSpace(mods))
	if mods == "" {
		return
	}
	for _, mod := range strings.Fields(mods) {
		switch mod {
		case "nocase":
			ys.Nocase = true
		case "wide":
			ys.Wide = true
		case "ascii":
			ys.ASCII = true
		}
	}
}

// stripYARAComments removes single-line (//) and multi-line (/* */) comments,
// plus import lines.
func stripYARAComments(text string) string {
	// Remove multi-line comments.
	reBlock := regexp.MustCompile(`(?s)/\*.*?\*/`)
	text = reBlock.ReplaceAllString(text, "")
	// Remove single-line comments.
	reLine := regexp.MustCompile(`//[^\n]*`)
	text = reLine.ReplaceAllString(text, "")
	// Remove import lines.
	reImport := regexp.MustCompile(`(?m)^\s*import\s+"[^"]*"\s*$`)
	text = reImport.ReplaceAllString(text, "")
	return text
}

// splitYARARules splits a file with multiple YARA rules into individual rule blocks.
func splitYARARules(text string) []string {
	// Match rule start patterns.
	reStart := regexp.MustCompile(`(?m)^\s*(?:private\s+|global\s+)*rule\s+\w+`)
	locs := reStart.FindAllStringIndex(text, -1)
	if len(locs) == 0 {
		return nil
	}

	var blocks []string
	for i, loc := range locs {
		start := loc[0]
		var end int
		if i+1 < len(locs) {
			end = locs[i+1][0]
		} else {
			end = len(text)
		}
		block := strings.TrimSpace(text[start:end])
		if block != "" {
			blocks = append(blocks, block)
		}
	}
	return blocks
}

func mapYARASeverity(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "low", "informational", "info":
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
