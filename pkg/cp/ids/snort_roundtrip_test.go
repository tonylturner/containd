// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package ids

import (
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestSnortContentExportImportRoundTrip(t *testing.T) {
	for _, tt := range []struct {
		name    string
		matches []config.ContentMatch
	}{
		{
			name: "nocase and depth",
			matches: []config.ContentMatch{
				{Pattern: "abc", Nocase: true, Depth: 10},
			},
		},
		{
			name: "all fields and multiple matches",
			matches: []config.ContentMatch{
				{Pattern: `quote"semi;comma,slash\end\`, Nocase: true, Depth: 60, Offset: 2},
				{Pattern: "DE AD BE EF", IsHex: true, Negate: true, Distance: 3, Within: 20},
				{Pattern: `literal\"and\;and\,`, Negate: true, Distance: -2, Within: 40},
				{Pattern: "plain"},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			original := config.IDSRule{ID: "snort-123", Proto: "tcp", ContentMatches: tt.matches}
			exported, err := ExportSnortRule(original)
			if err != nil {
				t.Fatal(err)
			}
			imported, err := ConvertSnortFile([]byte(exported))
			if err != nil {
				t.Fatal(err)
			}
			if len(imported) != 1 {
				t.Fatalf("got %d imported rules, want 1", len(imported))
			}
			if !reflect.DeepEqual(imported[0].ContentMatches, original.ContentMatches) {
				t.Fatalf("ContentMatches changed:\ngot  %#v\nwant %#v\nexported: %s",
					imported[0].ContentMatches, original.ContentMatches, exported)
			}
		})
	}
}
