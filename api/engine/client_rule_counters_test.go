// SPDX-License-Identifier: Apache-2.0

package engineapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestRuleCounters(t *testing.T) {
	excess := uint64(4)
	want := dpengine.RuleCounters{SnapshotVersion: "v2", Since: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC), Rules: []enforce.RuleCount{
		{RuleID: "police", Action: rules.ActionRateLimit, Packets: 9, Bytes: 900, ExcessDrops: &excess},
	}}
	var unavailable atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/firewall/counters" || r.Method != http.MethodGet {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		if unavailable.Load() {
			http.Error(w, "rule counters unavailable: no ruleset is applied", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()
	got, err := NewHTTPClient(srv.URL).RuleCounters(context.Background())
	if err != nil || got.SnapshotVersion != "v2" || !got.Since.Equal(want.Since) || len(got.Rules) != 1 || *got.Rules[0].ExcessDrops != 4 {
		t.Fatalf("RuleCounters = %+v, %v", got, err)
	}
	unavailable.Store(true)
	if _, err := NewHTTPClient(srv.URL).RuleCounters(context.Background()); err == nil || !strings.Contains(err.Error(), "no ruleset is applied") {
		t.Fatalf("unavailable err = %v", err)
	}
}
