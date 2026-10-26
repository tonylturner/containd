// SPDX-License-Identifier: Apache-2.0
package enforce

import (
	"fmt"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestManagementUnboundRuleset(t *testing.T) {
	live, err := mgmtpath.Devices()
	if err != nil {
		t.Fatal(err)
	}
	for _, denied := range [][]string{nil, live} {
		snap := &rules.Snapshot{LocalInput: []rules.LocalServiceRule{{
			ID: "auto-allow-mgmt-http", Proto: "tcp", Port: 18080,
			RecoverUnbound: true, Ifaces: []string{"missing-nic"}, DeniedIfaces: denied,
		}}}
		text, err := NewCompiler().CompileFirewall(snap)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(text, "missing-nic") || strings.Contains(text, "\n    tcp dport 18080 accept;") {
			t.Fatalf("unbound or unconstrained allow: %s", text)
		}
		if len(denied) > 0 && strings.Contains(text, "dport 18080") {
			t.Fatalf("disabled devices admitted: %s", text)
		}
		if len(denied) == 0 && len(live) > 0 {
			for _, name := range live {
				if !strings.Contains(text, fmt.Sprintf("%q", name)) {
					t.Fatalf("missing discovered NIC %s: %s", name, text)
				}
			}
		}
	}
}
