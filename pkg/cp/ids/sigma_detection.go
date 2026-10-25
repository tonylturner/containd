// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func buildDetectionConditions(det map[string]any) (config.IDSCondition, []string, error) {
	if len(det) == 0 {
		return config.IDSCondition{}, []string{`keyword "detection" not fully mapped`}, nil
	}
	selections := map[string]config.IDSCondition{}
	var notes []string
	var conditionExpr string
	for k, v := range det {
		if strings.EqualFold(k, "condition") {
			if s, ok := v.(string); ok {
				conditionExpr = s
			}
			if conditionExpr == "" {
				notes = append(notes, `keyword "condition" not fully mapped: expected a non-empty expression`)
			}
			continue
		}
		c, lost, err := buildSelectionCondition(v)
		if err != nil {
			return config.IDSCondition{}, nil, fmt.Errorf("selection %s: %w", k, err)
		}
		notes = append(notes, lost...)
		selections[k] = c
	}

	if conditionExpr == "" {
		if len(selections) == 1 {
			for _, c := range selections {
				return c, notes, nil
			}
		}
		return config.IDSCondition{}, nil, fmt.Errorf("sigma detection missing condition")
	}

	parser := newConditionParser(conditionExpr, selections)
	c, err := parser.parse()
	return c, append(notes, parser.notes...), err
}

func buildSelectionCondition(sel any) (config.IDSCondition, []string, error) {
	switch s := sel.(type) {
	case map[string]any:
		leaves, notes := buildLeafConditionsFromMap(s)
		if len(leaves) == 1 {
			return leaves[0], notes, nil
		}
		return config.IDSCondition{All: leaves}, notes, nil
	case []any:
		var anyConds []config.IDSCondition
		var notes []string
		if len(s) == 0 {
			notes = append(notes, `keyword "selection" not fully mapped: empty list`)
		}
		for _, el := range s {
			m, ok := el.(map[string]any)
			if !ok {
				return config.IDSCondition{}, nil, fmt.Errorf("selection list elements must be maps")
			}
			leaves, lost := buildLeafConditionsFromMap(m)
			notes = append(notes, lost...)
			if len(leaves) == 1 {
				anyConds = append(anyConds, leaves[0])
			} else {
				anyConds = append(anyConds, config.IDSCondition{All: leaves})
			}
		}
		if len(anyConds) == 1 {
			return anyConds[0], notes, nil
		}
		return config.IDSCondition{Any: anyConds}, notes, nil
	default:
		return config.IDSCondition{}, nil, fmt.Errorf("unsupported selection type %T", sel)
	}
}

func buildLeafConditionsFromMap(m map[string]any) ([]config.IDSCondition, []string) {
	var out []config.IDSCondition
	var notes []string
	if len(m) == 0 {
		notes = append(notes, `keyword "selection" not fully mapped: empty map`)
	}
	for rawField, v := range m {
		field, op, dropped := splitFieldModifier(rawField)
		for _, mod := range dropped {
			notes = append(notes, fmt.Sprintf("keyword %q not fully mapped in field %q", mod, rawField))
		}
		cond := config.IDSCondition{
			Field: normalizeField(field),
			Op:    op,
			Value: v,
		}
		if cond.Field == "" {
			notes = append(notes, `keyword "field" not fully mapped: empty name`)
		}
		// List equality is executable as membership; other list operators
		// need Sigma's OR/all semantics, which this converter does not map.
		switch v.(type) {
		case []any, []string, []int, []uint8, []uint16, []uint32, []uint64:
			if cond.Op == "equals" {
				cond.Op = "in"
			} else if cond.Op != "in" {
				modifier := strings.Split(rawField, "|")[1]
				notes = append(notes, fmt.Sprintf("keyword %q not fully mapped for list field %q", modifier, rawField))
			}
		}
		out = append(out, cond)
	}
	return out, notes
}

func splitFieldModifier(field string) (string, string, []string) {
	parts := strings.Split(field, "|")
	base := parts[0]
	if len(parts) == 1 {
		return base, "equals", nil
	}
	mod := strings.ToLower(parts[1])
	dropped := append([]string(nil), parts[2:]...)
	switch mod {
	case "contains", "gt", "lt", "in":
		return base, mod, dropped
	case "re", "regex":
		return base, "regex", dropped
	default:
		// Includes startswith/endswith: unanchored regex is not equivalent.
		return base, "equals", append(dropped, parts[1])
	}
}

func normalizeField(f string) string {
	f = strings.TrimSpace(f)
	if f == "" {
		return f
	}
	lf := strings.ToLower(f)
	if strings.HasPrefix(lf, "attr.") ||
		lf == "proto" || lf == "kind" || lf == "flowid" ||
		lf == "srcip" || lf == "dstip" || lf == "srcport" || lf == "dstport" {
		return lf
	}
	return "attr." + lf
}

// newConditionParser and helpers implement a tiny Sigma condition expression parser.
type conditionParser struct {
	tokens     []string
	pos        int
	selections map[string]config.IDSCondition
	notes      []string
}

func newConditionParser(expr string, selections map[string]config.IDSCondition) *conditionParser {
	re := regexp.MustCompile(`\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_\-*]+`)
	toks := re.FindAllString(strings.ToLower(expr), -1)
	p := &conditionParser{tokens: toks, selections: selections}
	if strings.TrimSpace(re.ReplaceAllString(expr, "")) != "" {
		p.notes = append(p.notes, `keyword "condition" not fully mapped: unsupported expression syntax`)
	}
	return p
}

func (p *conditionParser) parse() (config.IDSCondition, error) {
	c, err := p.parseOr()
	if err != nil {
		return config.IDSCondition{}, err
	}
	if p.pos != len(p.tokens) {
		return config.IDSCondition{}, fmt.Errorf("unexpected token %q", p.tokens[p.pos])
	}
	return c, nil
}

func (p *conditionParser) parseOr() (config.IDSCondition, error) {
	left, err := p.parseAnd()
	if err != nil {
		return config.IDSCondition{}, err
	}
	var ors []config.IDSCondition
	ors = append(ors, left)
	for p.match("or") {
		right, err := p.parseAnd()
		if err != nil {
			return config.IDSCondition{}, err
		}
		ors = append(ors, right)
	}
	if len(ors) == 1 {
		return ors[0], nil
	}
	return config.IDSCondition{Any: ors}, nil
}

func (p *conditionParser) parseAnd() (config.IDSCondition, error) {
	left, err := p.parseNot()
	if err != nil {
		return config.IDSCondition{}, err
	}
	var ands []config.IDSCondition
	ands = append(ands, left)
	for p.match("and") {
		right, err := p.parseNot()
		if err != nil {
			return config.IDSCondition{}, err
		}
		ands = append(ands, right)
	}
	if len(ands) == 1 {
		return ands[0], nil
	}
	return config.IDSCondition{All: ands}, nil
}

func (p *conditionParser) parseNot() (config.IDSCondition, error) {
	if p.match("not") {
		inner, err := p.parseNot()
		if err != nil {
			return config.IDSCondition{}, err
		}
		return config.IDSCondition{Not: &inner}, nil
	}
	return p.parsePrimary()
}

func (p *conditionParser) parsePrimary() (config.IDSCondition, error) {
	if p.match("(") {
		c, err := p.parseOr()
		if err != nil {
			return config.IDSCondition{}, err
		}
		if !p.match(")") {
			return config.IDSCondition{}, fmt.Errorf("missing )")
		}
		return c, nil
	}
	if p.pos >= len(p.tokens) {
		return config.IDSCondition{}, fmt.Errorf("unexpected end of condition")
	}
	tok := p.tokens[p.pos]
	p.pos++
	if c, ok := p.selections[tok]; ok {
		return c, nil
	}
	// Allow "selection*" wildcard as OR of matching selections.
	if strings.Contains(tok, "*") {
		prefix := strings.TrimRight(tok, "*")
		var anyConds []config.IDSCondition
		for name, c := range p.selections {
			if strings.HasPrefix(name, prefix) {
				anyConds = append(anyConds, c)
			}
		}
		if len(anyConds) == 0 {
			return config.IDSCondition{}, fmt.Errorf("unknown selection wildcard %q", tok)
		}
		if len(anyConds) == 1 {
			return anyConds[0], nil
		}
		return config.IDSCondition{Any: anyConds}, nil
	}
	// These legacy accepted literals have no executable translation. Preserve
	// the stored rule, but never let this empty leaf turn it into match-all.
	if _, err := strconv.Atoi(tok); err == nil || tok == "all" {
		p.notes = append(p.notes, fmt.Sprintf("keyword %q not fully mapped: literal %q", "condition", tok))
		return config.IDSCondition{}, nil
	}
	return config.IDSCondition{}, fmt.Errorf("unknown selection %q", tok)
}

func (p *conditionParser) match(t string) bool {
	if p.pos < len(p.tokens) && p.tokens[p.pos] == t {
		p.pos++
		return true
	}
	return false
}
