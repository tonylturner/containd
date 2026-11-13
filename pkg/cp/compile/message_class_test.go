// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"encoding/json"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestDS34ClassSchemaCompile(t *testing.T) {
	for _, class := range []string{"", "autonomous", "session"} {
		in := config.ICSPredicate{Protocol: "dnp3", Direction: "response", MessageClass: class, Masters: []uint16{1}}
		out := ICSPredicate(in)
		in.Masters[0] = 2
		if out.MessageClass != class || out.Masters[0] != 1 {
			t.Fatalf("mapping lost class or aliases station memory: %+v", out)
		}
		raw, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		if _, ok := fields["messageClass"]; ok != (class != "") {
			t.Fatalf("wrong selector presence: %s", raw)
		}
		var copy rules.ICSPredicate
		if err := json.Unmarshal(raw, &copy); err != nil || copy.MessageClass != class {
			t.Fatalf("snapshot roundtrip lost class: %+v %v", copy, err)
		}
	}
}
