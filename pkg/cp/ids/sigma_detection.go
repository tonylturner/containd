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

func buildDetectionConditions(det map[string]any) (config.IDSCondition, error) {
	if det == nil || len(det) == 0 {
		return config.IDSCondition{}, nil
	}
	selections := map[string]config.IDSCondition{}
	var conditionExpr string
	for k, v := range det {
		if strings.EqualFold(k, "condition") {
			if s, ok := v.(string); ok {
				conditionExpr = s
			}
			continue
		}
		c, err := buildSelectionCondition(v)
		if err != nil {
			return config.IDSCondition{}, fmt.Errorf("selection %s: %w", k, err)
		}
		selections[k] = c
	}

	if conditionExpr == "" {
		if len(selections) == 1 {
			for _, c := range selections {
				return c, nil
			}
		}
		return config.IDSCondition{}, fmt.Errorf("sigma detection missing condition")
	}

	parser := newConditionParser(conditionExpr, selections)
	return parser.parse()
}

func buildSelectionCondition(sel any) (config.IDSCondition, error) {
	switch s := sel.(type) {
	case map[string]any:
		leaves, err := buildLeafConditionsFromMap(s)
		if err != nil {
			return config.IDSCondition{}, err
		}
		if len(leaves) == 1 {
			return leaves[0], nil
		}
		return config.IDSCondition{All: leaves}, nil
	case []any:
		var anyConds []config.IDSCondition
		for _, el := range s {
			m, ok := el.(map[string]any)
			if !ok {
				return config.IDSCondition{}, fmt.Errorf("selection list elements must be maps")
			}
			leaves, err := buildLeafConditionsFromMap(m)
			if err != nil {
				return config.IDSCondition{}, err
			}
			if len(leaves) == 1 {
				anyConds = append(anyConds, leaves[0])
			} else {
				anyConds = append(anyConds, config.IDSCondition{All: leaves})
			}
		}
		if len(anyConds) == 1 {
			return anyConds[0], nil
		}
		return config.IDSCondition{Any: anyConds}, nil
	default:
		return config.IDSCondition{}, fmt.Errorf("unsupported selection type %T", sel)
	}
}

func buildLeafConditionsFromMap(m map[string]any) ([]config.IDSCondition, error) {
	var out []config.IDSCondition
	for rawField, v := range m {
		field, op := splitFieldModifier(rawField)
		cond := config.IDSCondition{
			Field: normalizeField(field),
			Op:    op,
			Value: v,
		}
		// Normalize list values to "in" if op is equals.
		switch v.(type) {
		case []any, []string, []int, []uint8, []uint16, []uint32, []uint64:
			if cond.Op == "equals" {
				cond.Op = "in"
			}
		}
		out = append(out, cond)
	}
	return out, nil
}

func splitFieldModifier(field string) (string, string) {
	parts := strings.Split(field, "|")
	base := parts[0]
	if len(parts) == 1 {
		return base, "equals"
	}
	mod := strings.ToLower(parts[1])
	switch mod {
	case "contains":
		return base, "contains"
	case "re", "regex":
		return base, "regex"
	case "startswith":
		return base, "regex"
	case "endswith":
		return base, "regex"
	case "gt":
		return base, "gt"
	case "lt":
		return base, "lt"
	default:
		return base, "equals"
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
}

func newConditionParser(expr string, selections map[string]config.IDSCondition) *conditionParser {
	re := regexp.MustCompile(`\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_\-*]+`)
	toks := re.FindAllString(strings.ToLower(expr), -1)
	return &conditionParser{tokens: toks, selections: selections}
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
	if tok == "1" || tok == "all" {
		return config.IDSCondition{}, nil
	}
	if strings.HasPrefix(tok, "selection") || p.selections[tok].Field != "" || p.selections[tok].All != nil || p.selections[tok].Any != nil || p.selections[tok].Not != nil {
		if c, ok := p.selections[tok]; ok {
			return c, nil
		}
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
	// If numeric literal, treat as empty (Sigma sometimes uses "1 of them").
	if _, err := strconv.Atoi(tok); err == nil {
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

