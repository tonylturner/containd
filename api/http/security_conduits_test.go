// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestSecurityConduitsDefaultAction(t *testing.T) {
	for _, tc := range []struct {
		stored      config.Action
		state       string
		defaultDeny bool
	}{
		{"", "block", true},
		{config.ActionDeny, "block", true},
		{config.ActionAllow, "unmodeled", false},
	} {
		t.Run(fmt.Sprintf("%q", tc.stored), func(t *testing.T) {
			m := &mockStore{cfg: &config.Config{
				System:   config.SystemConfig{Hostname: "containd"},
				Zones:    []config.Zone{{Name: "lan"}, {Name: "wan"}},
				Firewall: config.FirewallConfig{DefaultAction: tc.stored},
			}}
			rec := httptest.NewRecorder()
			NewServer(m, nil).ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/security/conduits", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
			}
			var got map[string]conduitResult
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			c, ok := got["lan→wan"]
			if !ok {
				t.Fatalf("missing lan→wan conduit in %s", rec.Body.String())
			}
			if c.State != tc.state || c.DefaultDeny != tc.defaultDeny {
				t.Fatalf("state %q defaultDeny %v, want %q %v", c.State, c.DefaultDeny, tc.state, tc.defaultDeny)
			}
			if hasGap := slices.Contains(c.Gaps, "No default-deny policy"); hasGap == tc.defaultDeny {
				t.Fatalf("gaps %q with defaultDeny %v", c.Gaps, tc.defaultDeny)
			}
		})
	}
}
