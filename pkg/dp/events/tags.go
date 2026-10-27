// SPDX-License-Identifier: Apache-2.0

package events

import "sort"

// KeyTags is the event attribute that carries a flow's TAG labels.
const KeyTags = "tags"

// WithTags returns attrs with the flow's TAG labels under KeyTags, or attrs
// itself when there are none. It copies attrs rather than change a map
// the caller may still hold.
func WithTags(attrs map[string]any, tags []string) map[string]any {
	if len(tags) == 0 {
		return attrs
	}
	out := make(map[string]any, len(attrs)+1)
	for k, v := range attrs {
		out[k] = v
	}
	out[KeyTags] = append([]string(nil), tags...)
	return out
}

// labelSet collects the TAG labels of a flow's events.
type labelSet map[string]struct{}

func (s labelSet) add(labels []string) {
	for _, l := range labels {
		s[l] = struct{}{}
	}
}

// sorted returns the labels in order, or nil when there are none.
func (s labelSet) sorted() []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, 0, len(s))
	for l := range s {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}
