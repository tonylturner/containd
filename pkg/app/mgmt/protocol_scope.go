// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

// publishScopeMigrations delivers the config store's transactional outbox.
// Events keep their original identity and timestamp across boots.
func publishScopeMigrations(ctx context.Context, stores mgmtStores) ([]dpevents.Event, error) {
	store, ok := stores.store.(interface {
		IndustrialScopeMigrations(context.Context) ([]config.IndustrialScopeMigration, error)
	})
	if !ok {
		return nil, nil
	}
	records, err := store.IndustrialScopeMigrations(ctx)
	if err != nil || len(records) == 0 {
		return nil, err
	}
	log, ok := stores.auditStore.(interface {
		AddOnce(context.Context, string, audit.Record) error
	})
	if !ok {
		return nil, fmt.Errorf("audit store does not support idempotent migration records")
	}
	var events []dpevents.Event
	for _, rec := range records {
		const kind = "config.industrial_scope.migrated"
		ids := strings.Join(rec.Removed, ", ")
		if err := log.AddOnce(ctx, fmt.Sprintf("%s.%d", kind, rec.ID), audit.Record{
			Timestamp: rec.Timestamp, Actor: "system", Source: "management",
			Action: kind, Target: ids, Result: "success", Detail: "Removed unchanged builtin IDS rules: " + ids,
		}); err != nil {
			return nil, err
		}
		events = append(events, dpevents.Event{ID: rec.ID, Timestamp: rec.Timestamp, Proto: "system", Kind: kind,
			Attributes: map[string]any{"removedRuleIds": rec.Removed}})
	}
	return events, nil
}
