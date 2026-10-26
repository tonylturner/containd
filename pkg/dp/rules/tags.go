// SPDX-License-Identifier: Apache-2.0

package rules

import "sort"

// Tags returns the sorted, distinct labels of every TAG entry that matches
// ctx, or nil. ctx carries a flow's opener-oriented tuple: source = opener,
// destination = server, Port = server port. A TAG entry has no ICS
// predicate or schedule (validation refuses them), so its labels are a
// function of the snapshot and that tuple alone.
func (e *Evaluator) Tags(ctx EvalContext) []string {
	var out []string
	for _, i := range e.tags {
		ce := &e.compiled[i]
		if ce.matches(ctx) && !contains(out, ce.Tag) {
			out = append(out, ce.Tag)
		}
	}
	sort.Strings(out)
	return out
}

// HasTags reports whether the snapshot has a TAG entry.
func (e *Evaluator) HasTags() bool { return len(e.tags) > 0 }

// TagsUseZones reports whether a TAG entry restricts zones, so that Tags
// needs the flow's zones in its context.
func (e *Evaluator) TagsUseZones() bool {
	for _, i := range e.tags {
		if len(e.compiled[i].SourceZones) > 0 || len(e.compiled[i].DestZones) > 0 {
			return true
		}
	}
	return false
}

// tagIndexes returns the indexes of the TAG entries.
func tagIndexes(entries []Entry) []int {
	var out []int
	for i, e := range entries {
		if e.Action == ActionTag && e.Tag != "" {
			out = append(out, i)
		}
	}
	return out
}
