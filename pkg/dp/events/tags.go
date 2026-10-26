// SPDX-License-Identifier: Apache-2.0

package events

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
