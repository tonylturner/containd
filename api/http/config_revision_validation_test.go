// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestConfigRevisionBodyValidationBeforeCompare(t *testing.T) {
	store := stageStore(t)
	ctx := context.Background()
	stale := testBaseRevision(store, ctx)
	if err := testMutateCandidate(store, ctx, func(c *config.Config) error { c.Description = "newer"; return nil }); err != nil {
		t.Fatal(err)
	}
	before, err := store.ReadSnapshot(ctx, config.SnapshotPair, true)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(store, nil)
	for _, test := range []struct{ method, path, body string }{
		{"POST", "/config/candidate", `{"description":17}`},
		{"PATCH", "/firewall/rules/old", `{"description":17}`},
		{"PATCH", "/firewall/rules/old", `{"schedule":{"startTime":17}}`},
		{"PATCH", "/firewall/rules/old", `{"ics":{"mode":17}}`},
		{"PATCH", "/firewall/rules/old", `{"ics":{"typeIds":["wrong"]}}`},
		{"PATCH", "/firewall/rules/old", `{"ics":{"mode":"monitor","mode":"enforce"}}`},
		{"PATCH", "/interfaces/missing", `{"alias":17}`},
		{"PATCH", "/interfaces/missing", `{"access":{"ssh":17}}`},
		{"PATCH", "/zones/spare", `{"description":17}`},
		{"PATCH", "/zones/spare", `{"slTarget":1.5}`},
		{"PATCH", "/zones/spare", `{"slOverrides":{"FR1":17}}`},
	} {
		t.Run(test.path+test.body, func(t *testing.T) {
			for _, revision := range []config.Revision{stale, before.Revision} {
				rec := casRequest(t, server, test.method, test.path, json.RawMessage(test.body), string(revision))
				if rec.Code != 400 {
					t.Fatalf("want body 400 before compare: %d %s", rec.Code, rec.Body)
				}
			}
		})
	}
	rec := casRequest(t, server, "PATCH", "/firewall/rules/old", map[string]string{"description": "valid"}, string(stale))
	if rec.Code != 412 {
		t.Fatalf("valid stale body: %d %s", rec.Code, rec.Body)
	}
	after, err := store.ReadSnapshot(ctx, config.SnapshotPair, true)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("rejections changed state: %v", err)
	}
}
