// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestZoneSetters(t *testing.T) {
	for _, tt := range []struct {
		name, doc string
		count     int
		wantError bool
	}{
		{"zone", `{"nftables":[{"rule":{"family":"inet","table":"foreign","chain":"raw","handle":19,"expr":[{"mangle":{"key":{"ct":{"key":"zone"}},"value":7}}]}}]}`, 1, false},
		{"xt", `{"nftables":[{"rule":{"family":"ip","table":"raw","chain":"PREROUTING","handle":20,"expr":[{"xt":{"type":"target","name":"CT"}}]}}]}`, 1, false},
		{"neither", `{"nftables":[{"rule":{"family":"ip6","table":"filter","chain":"forward","handle":21,"expr":[{"mangle":{"key":{"ct":{"key":"mark"}},"value":1}},{"accept":null}]}}]}`, 0, false},
		{"empty", `{"nftables":[]}`, 0, false},
		{"malformed", `{"nftables":[`, 0, true},
		{"missing", `{}`, 0, true},
		{"null", `{"nftables":null}`, 0, true},
		{"bad rule", `{"nftables":[{"rule":null}]}`, 0, true},
		{"null item", `{"nftables":[null]}`, 0, true},
		{"multiple item keys", `{"nftables":[{"table":{},"rule":{}}]}`, 0, true},
		{"bad expression", `{"nftables":[{"rule":{"family":"ip","table":"raw","chain":"pre","expr":[{"xt":2}]}}]}`, 0, true},
		{"null expression", `{"nftables":[{"rule":{"family":"ip","table":"raw","chain":"pre","expr":[null]}}]}`, 0, true},
		{"null mangle", `{"nftables":[{"rule":{"family":"ip","table":"raw","chain":"pre","expr":[{"mangle":null}]}}]}`, 0, true},
		{"nameless xt", `{"nftables":[{"rule":{"family":"ip","table":"raw","chain":"pre","expr":[{"xt":{}}]}}]}`, 0, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseZoneSetters([]byte(tt.doc))
			if (err != nil) != tt.wantError || len(got) != tt.count {
				t.Fatalf("ZoneSetters = %+v, %v", got, err)
			}
			if tt.name == "zone" && got[0] != (ZoneSetter{Family: "inet", Table: "foreign", Chain: "raw", Handle: 19}) {
				t.Fatalf("lost rule identity: %+v", got)
			}
		})
	}
}

func TestZoneSettersCommand(t *testing.T) {
	for _, tt := range []struct {
		name, output string
		exit         string
		wantError    bool
	}{
		{"empty ruleset", `{"nftables":[]}`, "0", false},
		{"listing failure", `{"nftables":[]}`, "1", true},
		{"invalid listing", `{`, "0", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "nft")
			// The helper rejects a table-specific read: the authority reader
			// must include other applications' rules and every family.
			script := "#!/bin/sh\n[ \"$#\" = 3 ] && [ \"$1\" = -j ] && [ \"$2\" = list ] && [ \"$3\" = ruleset ] || exit 9\n" +
				"printf '%s' '" + tt.output + "'\nexit " + tt.exit + "\n"
			if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			a := &NftApplier{Path: path}
			got, err := a.ZoneSetters(context.Background())
			if (err != nil) != tt.wantError || len(got) != 0 {
				t.Fatalf("ZoneSetters = %+v, %v", got, err)
			}
		})
	}
}
