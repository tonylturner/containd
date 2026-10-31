// SPDX-License-Identifier: Apache-2.0
package scopeaudit

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestRuleModesOutboxRedeliversOnce(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.db")
	s, err := config.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	c := config.DefaultConfig()
	c.SchemaVersion = "0.1.8"
	c.DataPlane.DPIMode = "learn"
	if err := s.SaveCandidate(ctx, c); err != nil {
		t.Fatal(err)
	}
	// Simulate loss of the management process after config commit, before audit delivery.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = config.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	log, err := audit.NewSQLiteStore(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	for range 2 {
		if _, err := Publish(ctx, s, log); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := log.List(ctx, 100)
	if err != nil || len(rows) != 2 {
		t.Fatal(rows, err)
	}
	kinds := map[string]bool{}
	for _, row := range rows {
		kinds[row.Action] = true
	}
	if !kinds[RuleModesKind] || !kinds[OrderedPolicyKind] {
		t.Fatal("combined upgrade missing audit", rows)
	}
	evs, err := Events(ctx, s)
	if err != nil || len(evs) != 2 || evs[0].Kind != RuleModesKind || evs[0].Attributes["bank"] != "candidate" ||
		evs[1].Kind != OrderedPolicyKind || evs[1].Attributes["bank"] != "candidate" {
		t.Fatal(evs, err)
	}
}
