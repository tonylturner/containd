// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

var counterNames = regexp.MustCompile(`(?m)^  counter (\S+) \{ \}$`)

// zeroCounters installs nothing and reads every counter of the last
// ruleset as zero.
type zeroCounters struct{ ruleset string }

func (z *zeroCounters) Apply(_ context.Context, ruleset string) error {
	z.ruleset = ruleset
	return nil
}
func (z *zeroCounters) ReadTable(context.Context, string) (enforce.TableLayout, error) {
	return enforce.TableLayout{}, nil
}
func (z *zeroCounters) ReadCounters(context.Context, string) (map[string]enforce.CounterValue, error) {
	out := map[string]enforce.CounterValue{}
	for _, name := range counterNames.FindAllStringSubmatch(z.ruleset, -1) {
		out[name[1]] = enforce.CounterValue{}
	}
	return out, nil
}

func TestRuleCountersHandler(t *testing.T) {
	dp, err := engine.New(engine.Config{Enforce: engine.EnforceConfig{Enabled: true, Applier: &zeroCounters{}}})
	if err != nil {
		t.Fatal(err)
	}
	get := func(method string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		ruleCountersHandler(dp).ServeHTTP(rec, httptest.NewRequest(method, "/internal/firewall/counters", nil))
		return rec
	}
	if rec := get(http.MethodGet); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("before apply: %d %s", rec.Code, rec.Body)
	}
	snap := rules.Snapshot{Version: "v3", Firewall: []rules.Entry{{ID: "police", Action: rules.ActionRateLimit, RateLimit: &rules.RateLimit{PacketsPerSecond: 1, Burst: 1}}}}
	if err := dp.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	rec := get(http.MethodGet)
	var body engine.RuleCounters
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("after apply: %d %s %v", rec.Code, rec.Body, err)
	}
	if body.SnapshotVersion != "v3" || body.Since.IsZero() || len(body.Rules) != 1 || body.Rules[0].ExcessDrops == nil {
		t.Fatalf("counters = %+v", body)
	}
	if rec := get(http.MethodPost); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}
}
