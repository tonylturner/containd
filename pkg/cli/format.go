// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

type table struct {
	headers []string
	rows    [][]string
}

func newTable(headers ...string) *table {
	return &table{headers: headers}
}

func (t *table) addRow(cols ...string) {
	t.rows = append(t.rows, cols)
}

func (t *table) render(out io.Writer) {
	if out == nil {
		return
	}
	if len(t.headers) == 0 {
		return
	}
	widths := make([]int, len(t.headers))
	for i, h := range t.headers {
		widths[i] = len(h)
	}
	for _, r := range t.rows {
		for i := 0; i < len(widths) && i < len(r); i++ {
			if l := len(r[i]); l > widths[i] {
				widths[i] = l
			}
		}
	}
	// Header
	for i, h := range t.headers {
		fmt.Fprintf(out, "%-*s ", widths[i], h)
	}
	fmt.Fprintln(out)
	// Underline
	for i := range t.headers {
		fmt.Fprintf(out, "%s ", strings.Repeat("-", widths[i]))
	}
	fmt.Fprintln(out)
	// Rows
	for _, r := range t.rows {
		for i := 0; i < len(widths); i++ {
			val := ""
			if i < len(r) {
				val = r[i]
			}
			fmt.Fprintf(out, "%-*s ", widths[i], val)
		}
		fmt.Fprintln(out)
	}
}

func kvTable(out io.Writer, m map[string]string) {
	t := newTable("KEY", "VALUE")
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.addRow(k, m[k])
	}
	t.render(out)
}

func joinCSV(ss []string) string {
	if len(ss) == 0 {
		return "—"
	}
	return strings.Join(ss, ",")
}

func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func yesNoStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format(time.RFC3339)
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "…"
}

func attrsSummary(attrs map[string]any, max int) string {
	if len(attrs) == 0 {
		return "—"
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := fmtAny(attrs[k])
		if v == "" {
			continue
		}
		parts = append(parts, k+"="+v)
	}
	return truncate(strings.Join(parts, " "), max)
}
