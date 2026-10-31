// SPDX-License-Identifier: Apache-2.0

// Package scopeaudit delivers durable industrial schema-upgrade evidence.
package scopeaudit

import (
	"context"
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

const Kind = "config.industrial_scope.migrated"

type Reader interface {
	IndustrialScopeMigrations(context.Context) ([]config.IndustrialScopeMigration, error)
}

// Events exposes the durable outbox directly, including migrations persisted
// after boot. Replays retain the original event identity and timestamp.
func Events(ctx context.Context, store config.Store) ([]dpevents.Event, error) {
	modes, modeErr := modeEvents(ctx, store)
	if modeErr != nil {
		return nil, modeErr
	}
	reader, ok := store.(Reader)
	if !ok {
		return modes, nil
	}
	records, err := reader.IndustrialScopeMigrations(ctx)
	if err != nil {
		return nil, err
	}
	events := modes
	for _, rec := range records {
		events = append(events, dpevents.Event{ID: rec.ID, Timestamp: rec.Timestamp, Proto: "system", Kind: Kind,
			Attributes: map[string]any{"removedRuleIds": rec.Removed, "updatedRuleIds": rec.Updated}})
	}
	return events, nil
}

// Publish idempotently copies transactional outbox records into the audit log.
// The outbox remains authoritative if delivery is interrupted or fails.
func Publish(ctx context.Context, store config.Store, log audit.Store) ([]dpevents.Event, error) {
	if err := publishModes(ctx, store, log); err != nil {
		return nil, err
	}
	reader, ok := store.(Reader)
	if !ok {
		return nil, nil
	}
	records, err := reader.IndustrialScopeMigrations(ctx)
	if err != nil || len(records) == 0 {
		if err != nil {
			return nil, err
		}
		return Events(ctx, store)
	}
	once, ok := log.(interface {
		AddOnce(context.Context, string, audit.Record) error
	})
	if !ok {
		return nil, fmt.Errorf("audit store does not support idempotent migration records")
	}
	for _, rec := range records {
		ids := strings.Join(append(append([]string{}, rec.Removed...), rec.Updated...), ", ")
		detail := "Removed unchanged builtin IDS rules: " + strings.Join(rec.Removed, ", ")
		if len(rec.Updated) > 0 {
			detail += "; Updated unchanged builtin IDS rules: " + strings.Join(rec.Updated, ", ")
		}
		if err := once.AddOnce(ctx, fmt.Sprintf("%s.%d", Kind, rec.ID), audit.Record{
			Timestamp: rec.Timestamp, Actor: "system", Source: "management", Action: Kind,
			Target: ids, Result: "success", Detail: detail,
		}); err != nil {
			return nil, err
		}
	}
	return Events(ctx, store)
}
